import 'dart:async';

import 'package:dsh_client/dsh_client.dart';

import '../../l10n/l10n.dart';
import '../link_status.dart';
import 'local_forward.dart';
import 'remote_bootstrap.dart';
import 'ssh_host_config.dart';
import 'ssh_transport.dart';

/// What the person is asked on first contact with a host.
class HostKeyPrompt {
  const HostKeyPrompt({required this.hostName, required this.address, required this.key});

  final String hostName;
  final String address;
  final PresentedHostKey key;
}

/// Shows the "trust this host?" question; true to pin and continue.
typedef HostKeyPrompter = Future<bool> Function(HostKeyPrompt prompt);

/// Persists a newly trusted key for the host.
typedef HostKeyPinner = Future<void> Function(PresentedHostKey key);

/// Logs in to the `dsh web` behind the tunnel.
typedef DshClientConnector = Future<DshClient> Function({
  required Uri baseUri,
  required String token,
  required String hostHeader,
});

Future<DshClient> _defaultConnector({required Uri baseUri, required String token, required String hostHeader}) =>
    DshClient.connect(
      baseUri: baseUri,
      token: token,
      hostHeader: hostHeader,
      // A remote Host's `session/list` is megabytes of JSON: every stored
      // session, archived and subagent ones included, each with its
      // projections. Decoding that on the UI isolate is what froze the app
      // during startup sync — the frames simply stopped being drawn. The
      // background read hands the HTTP, the gzip and the JSON to a worker
      // isolate; only the rows cross back.
      backgroundSessionLists: true,
      // A tunnel is a slow, lossy pipe: one TCP connect opens one SSH
      // channel, and a request that has not answered in 45 s is not going
      // to. The stock 120 s request timeout turned a half-open tunnel into
      // a two-minute spinner.
      connectTimeout: const Duration(seconds: 20),
      requestTimeout: const Duration(seconds: 45),
      // A ping's pong must come back within one interval, or `dart:io`
      // closes the socket. Over a tunnel that carries a conversation's whole
      // opening snapshot in one WebSocket message, the frame itself can take
      // longer than 15 s — and a closed socket means re-reading the whole
      // snapshot again. The stock 15 s interval turned one slow link into an
      // endless reload: the app downloaded the same snapshot dozens of times
      // and the UI never got a frame.
      muxOptions: const MuxOptions(pingInterval: Duration(seconds: 90)),
    );

/// Trust-on-first-use check against the pinned fingerprint.
enum HostKeyVerdict { trusted, unknown, mismatch }

HostKeyVerdict checkHostKey(SshHostConfig config, PresentedHostKey key) {
  final pinned = config.hostKeyFingerprint;
  if (pinned == null || pinned.isEmpty) return HostKeyVerdict.unknown;
  return pinned == key.fingerprint ? HostKeyVerdict.trusted : HostKeyVerdict.mismatch;
}

HostLinkError hostKeyMismatchError(SshHostConfig config, PresentedHostKey key) => HostLinkError(
  HostLinkErrorKind.hostKeyMismatch,
  appL10n.remoteErrFingerprintChanged,
  detail: appL10n.remoteHostKeyMismatchDetail(config.hostKeyFingerprint.toString(), key.fingerprint, key.shortType),
);

/// SSH remote host: connect → verify host key → start/reuse `dsh web` →
/// local forward → DshClient login; then keepalive and reconnect.
///
/// Mirrors dsh-tauri's SSH plugin flow (`bootstrap.utils.ts`, `transport.ts`):
/// the remote server binds 127.0.0.1 only, the token comes from its log, and
/// the client presents `Host: 127.0.0.1:<remote port>` so DSH's Host fence
/// accepts requests that arrive through the tunnel.
class SshHostLink implements HostLink {
  SshHostLink({
    required this._config,
    required this._loadSecrets,
    this.promptHostKey,
    this.pinHostKey,
    SshTransportFactory? transportFactory,
    DshClientConnector? connectClient,
    Stream<void>? kicks,
    Backoff? backoff,
    this.remoteEnvironment = const {},
    this.keepAliveInterval = const Duration(seconds: 15),
    this.keepAliveTimeout = const Duration(seconds: 10),
    this.tunnelProbeTimeout = const Duration(seconds: 10),
    this.connectBudget = const Duration(seconds: 120),
    this.retryFirstOpen = true,
  }) : _transportFactory = transportFactory ?? DartSshTransport.connect,
       _connectClient = connectClient ?? _defaultConnector,
       _backoff = backoff ?? Backoff() {
    _kickSub = kicks?.listen((_) => kick());
  }

  SshHostConfig _config;
  final Future<SshSecrets> Function() _loadSecrets;
  final HostKeyPrompter? promptHostKey;
  final HostKeyPinner? pinHostKey;
  final SshTransportFactory _transportFactory;
  final DshClientConnector _connectClient;
  final Backoff _backoff;
  final Map<String, String> remoteEnvironment;
  final Duration keepAliveInterval;
  final Duration keepAliveTimeout;

  /// Bounds the initial probe and subsequent forwarded channel opens.
  final Duration tunnelProbeTimeout;

  /// Bounds one whole attempt: SSH → remote `dsh web` → tunnel → sign-in.
  ///
  /// Every phase has a timeout of its own, but their sum was minutes — and
  /// the retry loop then did that again, eight times. One attempt now gets a
  /// budget, and whatever is left of it is all the remote start may use.
  final Duration connectBudget;

  /// False for "测试连接": report the first failure instead of retrying.
  final bool retryFirstOpen;

  final _statuses = StreamController<HostLinkStatus>.broadcast(sync: true);
  final _clients = StreamController<DshClient>.broadcast();
  final _delay = InterruptibleDelay();
  StreamSubscription<void>? _kickSub;
  StreamSubscription<DshConnectionState>? _muxSub;
  HostLinkStatus _status = HostLinkStatus.idle;

  SshTransport? _transport;
  SshTransport? _connectingTransport;
  Completer<SshTransport> _ready = Completer<SshTransport>();
  LocalForwarder? _forwarder;
  RemoteDshEndpoint? _endpoint;
  DshClient? _client;
  Future<DshClient>? _opening;
  Timer? _keepAlive;
  int _missedPings = 0;
  bool _closed = false;
  bool _recovering = false;
  bool _needsRelogin = false;
  bool _forceRestart = false;

  SshHostConfig get config => _config;

  /// Takes a rename, a new working directory or a re-pinned key without
  /// touching the SSH session (a new address or login needs a new link).
  void updateConfig(SshHostConfig next) {
    _config = _config.copyWith(
      name: next.name,
      workingDirectory: () => next.workingDirectory,
      hostKeyType: () => next.hostKeyType,
      hostKeyFingerprint: () => next.hostKeyFingerprint,
    );
  }

  RemoteDshEndpoint? get endpoint => _endpoint;

  /// The local forward port (null before the first tunnel).
  int? get localPort => _forwarder?.port;

  /// Configured working directory with `~` resolved on the remote.
  String? get resolvedWorkingDirectory => RemoteDshBootstrap.absolutePath(_config.workingDirectory, _endpoint?.home);

  @override
  HostLinkStatus get status => _status;

  @override
  DshClient? get currentClient => _status.isConnected ? _client : null;

  @override
  Stream<HostLinkStatus> get statuses => _statuses.stream;

  @override
  Stream<DshClient> get clients => _clients.stream;

  void _emit(HostLinkStatus next) {
    if (_closed && next.phase != HostLinkPhase.idle) return;
    _status = next;
    _statuses.add(next);
  }

  @override
  Future<DshClient> open() {
    if (_closed) return Future.error(StateError('link closed'));
    final client = _client;
    if (client != null && _status.isConnected) return Future.value(client);
    return _opening ??= _openFirst().whenComplete(() => _opening = null);
  }

  Future<DshClient> _openFirst() async {
    _backoff.reset();
    _emit(const HostLinkStatus(HostLinkPhase.connecting, step: HostLinkStep.connect));
    try {
      return await _connectOnce();
    } on HostLinkError catch (e) {
      if (!e.retryable || !retryFirstOpen) {
        _fail(e);
        rethrow;
      }
      return _recover(e);
    } catch (e) {
      final error = HostLinkError(
        HostLinkErrorKind.other,
        appL10n.commonConnectionFailed,
        detail: '$e',
        retryable: true,
      );
      if (!retryFirstOpen) {
        _fail(error);
        throw error;
      }
      return _recover(error);
    }
  }

  void _fail(HostLinkError error) {
    _teardownTransport();
    _emit(HostLinkStatus(HostLinkPhase.failed, step: _status.step, completed: _status.completed, error: error));
  }

  void _checkOpen() {
    if (_closed) throw StateError('link closed');
  }

  /// Ends the attempt when it has used up its budget.
  ///
  /// Without this the phases simply added up: a 60 s remote start followed by
  /// a 45 s sign-in is two minutes of spinner before anybody learns that the
  /// attempt was doomed.
  void _checkBudget(DateTime deadline) {
    if (_closed) throw StateError('link closed');
    if (DateTime.now().isAfter(deadline)) {
      throw HostLinkError(
        HostLinkErrorKind.unreachable,
        appL10n.remoteErrSshUnresponsive,
        detail: 'the attempt used up its ${connectBudget.inSeconds}s budget',
        retryable: true,
      );
    }
  }

  /// One full attempt. Reuses the forwarder and, when the remote endpoint is
  /// unchanged, the existing DshClient.
  Future<DshClient> _connectOnce() async {
    var step = _status.withStep(HostLinkStep.connect);
    void at(HostLinkStep s, {String? detail}) {
      step = step.withStep(s, detail: detail);
      _emit(step);
    }

    final deadline = DateTime.now().add(connectBudget);
    at(HostLinkStep.connect, detail: _config.address);
    final secrets = await _loadSecrets();
    _checkOpen();
    final transport = await _transportFactory(SshConnectParams.of(_config, secrets), (key) async {
      if (_closed) return false;
      at(HostLinkStep.verifyHostKey, detail: '${key.shortType} ${key.fingerprint}');
      switch (checkHostKey(_config, key)) {
        case HostKeyVerdict.trusted:
          return true;
        case HostKeyVerdict.mismatch:
          throw hostKeyMismatchError(_config, key);
        case HostKeyVerdict.unknown:
          final prompt = promptHostKey;
          if (prompt == null) {
            throw HostLinkError(
              HostLinkErrorKind.hostKeyUnverified,
              appL10n.remoteErrFingerprintUnconfirmed,
              detail: '${key.shortType} ${key.fingerprint}',
            );
          }
          final ok = await prompt(HostKeyPrompt(hostName: _config.name, address: _config.address, key: key));
          if (_closed) return false;
          if (!ok) {
            throw HostLinkError(HostLinkErrorKind.hostKeyRejected, appL10n.remoteHostTrustCancelled);
          }
          _config = _config.copyWith(hostKeyType: () => key.type, hostKeyFingerprint: () => key.fingerprint);
          await pinHostKey?.call(key);
          if (_closed) return false;
          return true;
      }
    });
    if (_closed) {
      transport.close();
      throw StateError('link closed');
    }
    // Own the authenticated connection while bootstrap/probe are pending.
    _connectingTransport = transport;
    at(HostLinkStep.startDsh, detail: appL10n.remoteCheckingDsh);
    try {
      // Whatever is left of this attempt's budget is all the remote start
      // may use. A remote that needs a full minute to boot is already the
      // slow case; a budget that is nearly spent must not start one at all.
      final left = deadline.difference(DateTime.now());
      final bootstrap = RemoteDshBootstrap(
        transport,
        launchCommand: _config.launchCommand,
        workingDirectory: _config.workingDirectory,
        environment: remoteEnvironment,
        startTimeout: left < const Duration(seconds: 60) ? left : const Duration(seconds: 60),
      );
      final endpoint = await bootstrap.ensureRunning(
        forceRestart: _forceRestart,
        onDetail: (d) => at(HostLinkStep.startDsh, detail: d),
      );
      _checkOpen();
      _checkBudget(deadline);
      _forceRestart = false;

      at(HostLinkStep.tunnel, detail: '127.0.0.1:${endpoint.port}');
      try {
        // Destroy a late channel too: Future.timeout does not cancel the
        // underlying SSH channel-open request.
        await transport
            .openTunnel('127.0.0.1', endpoint.port)
            .then((channel) => channel.destroy())
            .timeout(tunnelProbeTimeout);
      } catch (e) {
        // A reused DSH whose port no longer answers: start a fresh one.
        if (endpoint.reused && e is TunnelRefused) _forceRestart = true;
        throw HostLinkError(
          HostLinkErrorKind.tunnelFailed,
          appL10n.remoteErrDshPort,
          detail: '$e',
          retryable: true,
          diagnosticCode: e is TimeoutException
              ? HostLinkDiagnosticCode.sshTunnelTimedOut
              : e is TunnelRefused
              ? HostLinkDiagnosticCode.sshTunnelRefused
              : HostLinkDiagnosticCode.sshTunnelFailed,
        );
      }
      _checkOpen();
      _checkBudget(deadline);
      final previous = _endpoint;
      _endpoint = endpoint;
      if (_forwarder == null) {
        final forwarder = await LocalForwarder.bind(_openChannel);
        if (_closed) {
          await forwarder.close();
          throw StateError('link closed');
        }
        _forwarder = forwarder;
      }
      _connectingTransport = null;
      _installTransport(transport);

      at(HostLinkStep.login);
      _checkBudget(deadline);
      final client = await _ensureClient(endpoint, previous);
      _checkOpen();
      _emit(
        HostLinkStatus(
          HostLinkPhase.connected,
          completed: HostLinkStep.values.toSet(),
          detail: endpoint.reused ? appL10n.remoteDshReused : appL10n.remoteDshStarted,
        ),
      );
      _startKeepAlive();
      return client;
    } catch (e) {
      transport.close();
      if (identical(_transport, transport)) _teardownTransport();
      rethrow;
    } finally {
      if (identical(_connectingTransport, transport)) _connectingTransport = null;
    }
  }

  Future<DshClient> _ensureClient(RemoteDshEndpoint endpoint, RemoteDshEndpoint? previous) async {
    final existing = _client;
    final sameServer = previous != null && previous.port == endpoint.port && previous.token == endpoint.token;
    if (existing != null && sameServer && !_needsRelogin) {
      // Same process behind the same port: the cookie still works and the mux
      // reconnects through the forwarder by itself. Skip its backoff.
      existing.mux.reconnect();
      return existing;
    }
    final DshClient client;
    try {
      client = await _connectClient(
        baseUri: Uri(scheme: 'http', host: '127.0.0.1', port: _forwarder!.port),
        token: endpoint.token,
        hostHeader: endpoint.authority,
      );
    } on DshHttpException catch (e) {
      if (e.statusCode == 401 && endpoint.reused) {
        // Stale log from a process that's gone or restarted: start fresh.
        _forceRestart = true;
      }
      throw HostLinkError(
        HostLinkErrorKind.loginFailed,
        e.statusCode == 401 ? appL10n.remoteErrDshTokenRejected : appL10n.remoteErrDshSignIn,
        detail: '$e',
        retryable: true,
      );
    } on DshException catch (e) {
      throw HostLinkError(HostLinkErrorKind.tunnelFailed, appL10n.remoteErrDshTunnel, detail: '$e', retryable: true);
    }
    if (_closed) {
      await client.close().catchError((_) {});
      throw StateError('link closed');
    }
    _needsRelogin = false;
    _client = client;
    _watchMux(client);
    if (existing != null) {
      _clients.add(client);
      unawaited(existing.close().catchError((_) {}));
    }
    return client;
  }

  void _watchMux(DshClient client) {
    unawaited(_muxSub?.cancel());
    _muxSub = client.mux.states.listen((state) {
      if (state == DshConnectionState.unauthorized && identical(client, _client)) {
        _needsRelogin = true;
        _lost(HostLinkError(HostLinkErrorKind.loginFailed, appL10n.remoteErrDshSignInExpired, retryable: true));
      }
    });
  }

  /// SSH answers but the mux can't get through: if nothing listens on DSH's
  /// port any more, reconnect, which starts it again.
  Future<void> _probeDsh() async {
    final transport = _transport;
    final endpoint = _endpoint;
    if (transport == null || endpoint == null || !_status.isConnected) return;
    try {
      // A channel that opens after the timeout is still closed.
      final probe = transport.openTunnel('127.0.0.1', endpoint.port).then((channel) => channel.destroy());
      await probe.timeout(const Duration(seconds: 5));
    } catch (_) {
      if (!identical(transport, _transport)) return;
      _backoff.reset();
      _lost(HostLinkError(HostLinkErrorKind.dshStartFailed, appL10n.remoteErrDshStopped, retryable: true));
    }
  }

  void _installTransport(SshTransport transport) {
    _transport = transport;
    if (!_ready.isCompleted) _ready.complete(transport);
    unawaited(
      transport.done.then((_) {
        if (identical(_transport, transport)) {
          _lost(
            HostLinkError(
              HostLinkErrorKind.unreachable,
              appL10n.remoteErrSshDisconnected,
              retryable: true,
              diagnosticCode: HostLinkDiagnosticCode.sshTransportEnded,
            ),
          );
        }
      }),
    );
  }

  void _teardownTransport() {
    _keepAlive?.cancel();
    _keepAlive = null;
    final transport = _transport;
    _transport = null;
    if (_ready.isCompleted) _ready = Completer<SshTransport>();
    transport?.close();
    _forwarder?.dropConnections();
  }

  /// Channels for the forwarder: waits (bounded) for a live SSH connection.
  Future<TunnelChannel> _openChannel() async {
    _checkOpen();
    final transport = _transport ?? await _ready.future.timeout(const Duration(seconds: 20));
    _checkOpen();
    final port = _endpoint?.port;
    if (port == null) throw StateError('no remote endpoint yet');
    var abandoned = false;
    try {
      return await transport
          .openTunnel('127.0.0.1', port)
          .then((channel) {
            if (abandoned || _closed || !identical(transport, _transport)) {
              channel.destroy();
              throw StateError('SSH channel no longer active');
            }
            return channel;
          })
          .timeout(tunnelProbeTimeout);
    } catch (_) {
      // A timeout does not cancel the SSH request: dispose a late success.
      abandoned = true;
      rethrow;
    }
  }

  void _startKeepAlive() {
    _keepAlive?.cancel();
    _missedPings = 0;
    _keepAlive = Timer.periodic(keepAliveInterval, (_) => unawaited(_keepAliveTick()));
  }

  Future<void> _keepAliveTick() async {
    if (!await _ping(keepAliveTimeout)) return;
    final mux = _client?.mux.state;
    if (mux == DshConnectionState.connecting || mux == DshConnectionState.reconnecting) await _probeDsh();
  }

  Future<bool> _ping(Duration timeout) async {
    final transport = _transport;
    if (transport == null || _closed) return false;
    try {
      await transport.ping(timeout: timeout);
      _missedPings = 0;
      return true;
    } catch (_) {
      _missedPings++;
      if (_missedPings >= 2 && identical(transport, _transport)) {
        _lost(
          HostLinkError(
            HostLinkErrorKind.unreachable,
            appL10n.remoteErrSshUnresponsive,
            retryable: true,
            diagnosticCode: HostLinkDiagnosticCode.sshKeepaliveMissed,
          ),
        );
      }
      return false;
    }
  }

  void _lost(HostLinkError reason) {
    if (_closed || _recovering || _status.phase == HostLinkPhase.failed) return;
    if (_status.phase != HostLinkPhase.connected) return;
    _teardownTransport();
    unawaited(_recover(reason).then((_) {}, onError: (_) {}));
  }

  /// Reconnect loop with backoff. Resolves with the (possibly new) client.
  Future<DshClient> _recover(HostLinkError reason) async {
    _recovering = true;
    var last = reason;
    try {
      while (!_closed) {
        if (_backoff.exhausted) {
          final error = HostLinkError(
            last.kind,
            last.message,
            detail: [if (last.detail != null) last.detail!, appL10n.remoteRetryCount(_backoff.attempt)].join('\n'),
            retryable: true,
            diagnosticCode: last.diagnosticCode,
          );
          _fail(error);
          throw error;
        }
        final delay = _backoff.next();
        _emit(
          HostLinkStatus(
            HostLinkPhase.reconnecting,
            attempt: _backoff.attempt,
            error: last,
            nextRetryAt: DateTime.now().add(delay),
          ),
        );
        await _delay.wait(delay);
        if (_closed) break;
        try {
          final client = await _connectOnce();
          _backoff.reset();
          return client;
        } on HostLinkError catch (e) {
          if (_closed) break;
          if (!e.retryable) {
            _fail(e);
            rethrow;
          }
          last = e;
        } catch (e) {
          if (_closed) break;
          last = HostLinkError(HostLinkErrorKind.other, appL10n.commonConnectionFailed, detail: '$e', retryable: true);
        }
      }
      throw StateError('link closed');
    } finally {
      _recovering = false;
    }
  }

  /// Kills the current SSH connection as if the network dropped (live tests).
  void debugDropTransport() => _transport?.close();

  @override
  void kick() {
    if (_closed) return;
    switch (_status.phase) {
      case HostLinkPhase.connected:
        // Network changed under us: a quick ping tells whether the socket
        // survived; a dead one triggers reconnect without waiting for the
        // regular keepalive.
        unawaited(() async {
          final alive = await _ping(const Duration(seconds: 5));
          if (!alive) {
            _backoff.reset();
            _lost(
              HostLinkError(
                HostLinkErrorKind.unreachable,
                appL10n.remoteErrSshNetworkChanged,
                retryable: true,
                diagnosticCode: HostLinkDiagnosticCode.sshKickProbeFailed,
              ),
            );
          }
        }());
      case HostLinkPhase.reconnecting:
        _backoff.reset();
        _delay.skip();
      case HostLinkPhase.failed:
        if (_status.error?.retryable ?? false) retry();
      case HostLinkPhase.idle || HostLinkPhase.connecting:
        break;
    }
  }

  @override
  void retry() {
    if (_closed) return;
    if (_status.phase == HostLinkPhase.reconnecting) {
      _backoff.reset();
      _delay.skip();
      return;
    }
    if (_status.phase == HostLinkPhase.connecting) {
      // The user asked for a fresh start. The attempt in flight may be
      // waiting out a remote `dsh web` start or a sign-in that will not
      // answer; abandon it and let the retry loop open again.
      _abandonAttempt();
      return;
    }
    if (_status.isBusy) return;
    if (_status.phase == HostLinkPhase.connected) unawaited(_probeDsh());
    if (_status.phase == HostLinkPhase.failed || _status.phase == HostLinkPhase.idle) {
      unawaited(open().then((_) {}, onError: (_) {}));
    }
  }

  /// Ends the attempt in flight so the next one starts on the new network.
  ///
  /// Closing the transport makes the pending phase fail, which the retry loop
  /// turns into the next attempt. The SSH handshake itself is not cancellable
  /// from here — it owns its own timeouts — but everything after it is.
  void _abandonAttempt() {
    _backoff.reset();
    _connectingTransport?.close();
    _teardownTransport();
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _emit(HostLinkStatus.idle);
    _closed = true;
    _delay.cancel();
    final connecting = _connectingTransport;
    _connectingTransport = null;
    connecting?.close();
    await _kickSub?.cancel();
    await _muxSub?.cancel();
    _teardownTransport();
    await _forwarder?.close();
    _forwarder = null;
    final client = _client;
    _client = null;
    if (client != null) await client.close().catchError((_) {});
    await _statuses.close();
    await _clients.close();
  }
}

/// Connects just far enough to read the server's host key, without logging
/// in: used to ask "trust this host?" before a host becomes active.
Future<PresentedHostKey> fetchHostKey(SshHostConfig config, {SshTransportFactory? transportFactory}) async {
  PresentedHostKey? seen;
  // A dummy password: verification happens before authentication, and the
  // verifier refuses, so nothing is ever sent.
  final params = SshConnectParams(
    host: config.host.trim(),
    port: config.port,
    username: config.user.trim(),
    auth: SshAuthMethod.password,
    secrets: const SshSecrets(password: 'x'),
  );
  try {
    final transport = await (transportFactory ?? DartSshTransport.connect)(params, (key) {
      seen = key;
      return false;
    });
    transport.close();
  } catch (e) {
    if (seen != null) return seen!;
    if (e is HostLinkError) rethrow;
    throw HostLinkError(HostLinkErrorKind.unreachable, appL10n.remoteErrReadFingerprint, detail: '$e', retryable: true);
  }
  if (seen != null) return seen!;
  throw HostLinkError(HostLinkErrorKind.other, appL10n.remoteErrNoFingerprint);
}
