// Portions derived from ds-harness-remote (https://github.com/liguobao/ds-harness-remote), MIT, Copyright (c) 2026 DSH Remote contributors. See THIRD_PARTY_NOTICES.md.
// Account sign-in, device identity, Host directory/pinning and connect.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as hashes;
import 'package:dsh_client/dsh_client.dart';

import '../carrier/tunnel_carrier.dart';
import '../channel/rpc_client.dart';
import '../channel/secure_channel.dart';
import '../crypto/noise_ik.dart';
import '../protocol/control.dart' show maxRemoteCapabilityEntries;
import '../server/server_api.dart';
import '../state.dart';
import '../transport/peer_connection.dart';
import '../transport/relay_transport.dart';
import '../transport/transport.dart';
import '../transport/webrtc_transport.dart';
import '../util/bytes.dart';
import 'secret_store.dart';

// Accounts using the same storage object and server keys share commit order.
// An Expando does not keep an otherwise unreachable SecretStore alive.
class _AccountStorageState {
  Future<void> credentialWrites = Future<void>.value();
  int signInEpoch = 0;
}

final _accountStorageStates = Expando<Map<String, _AccountStorageState>>();

/// The signed-in account on one Server.
class RemoteUser {
  const RemoteUser({required this.account, required this.deviceId, required this.serverUrl, this.provider});

  /// Account name (email or OAuth account id) as the Server reports it.
  final String account;

  /// This app's client device id on the Server.
  final String deviceId;
  final Uri serverUrl;

  /// The provider this device signed in with (github, zhihu, google, password);
  /// null for credentials stored before providers were recorded.
  final String? provider;

  @override
  String toString() => 'RemoteUser($account on $serverUrl)';
}

enum RemoteHostTrust {
  /// Pinned identity key matches the Server descriptor.
  pinned,

  /// Never connected: the key will be pinned on first connect.
  unpinned,

  /// The Server now reports a different key than the pinned one: connecting
  /// fails closed until the user re-trusts it ([RemoteAccount.forgetHost]).
  keyChanged,

  /// The descriptor could not be fetched.
  unknown,
}

/// A Host this account may connect to.
class RemoteHost {
  const RemoteHost({
    required this.id,
    required this.name,
    required this.platform,
    required this.online,
    required this.trust,
    this.harnessVersion,
    this.pluginVersion,
    this.lastSeenAt,
    this.identityKey,
    this.pinnedIdentityKey,
    this.membershipId,
  });

  /// Host device id.
  final String id;

  /// Untrusted display name (escape / truncate in UI).
  final String name;

  /// `linux`, `darwin`, `win32`, ...
  final String platform;
  final bool online;

  /// DSH (Harness) version running on the Host, when reported.
  final String? harnessVersion;

  /// ds-harness-remote plugin version on the Host.
  final String? pluginVersion;
  final DateTime? lastSeenAt;

  /// Noise static key from the Server descriptor.
  final String? identityKey;

  /// Key pinned on this device, if any.
  final String? pinnedIdentityKey;
  final RemoteHostTrust trust;
  final String? membershipId;

  /// `ABCD EF01 2345` of [identityKey] (compare with the Host's display).
  String? get fingerprint => identityKey == null ? null : formatFingerprint(identityFingerprint(identityKey!));

  @override
  String toString() => 'RemoteHost($name, $id, ${online ? 'online' : 'offline'}, ${trust.name})';
}

/// Decides whether to trust a Host seen for the first time (show
/// [RemoteHost.fingerprint] and ask the user). Return `false` to refuse.
typedef HostTrustPrompt = Future<bool> Function(RemoteHost host);

/// An in-progress QR / browser sign-in.
///
/// Open [loginUrl] in a Custom Tab or the browser (or render it as a QR
/// code for another phone); [result] completes once the account authorized
/// this device, polling the Server every 2 s until [expiresAt].
class RemoteLogin {
  RemoteLogin._(this.loginUrl, this.providerId, this.expiresAt, this._result, this._cancel);

  final Uri loginUrl;
  final String providerId;
  final DateTime expiresAt;
  final Future<RemoteUser> _result;
  final void Function() _cancel;

  /// Completes with the signed-in user, or fails with
  /// [RemoteConnectException] (`LOGIN_EXPIRED`, `LOGIN_CANCELLED`, ...).
  Future<RemoteUser> get result => _result;

  /// Cancels before the local credential write starts; [result] then fails
  /// with `LOGIN_CANCELLED`. Once that atomic write has started, cancellation
  /// cannot undo it and [result] reports the actual commit outcome.
  /// Registration already processed by the Server is not revoked.
  void cancel() => _cancel();
}

class _Identity {
  _Identity({
    required this.deviceId,
    required this.privateKey,
    required this.publicKey,
    required this.name,
    required this.platform,
  });

  factory _Identity.fromJson(JsonMap json) => _Identity(
    deviceId: json['deviceId']! as String,
    privateKey: json['privateKey']! as String,
    publicKey: json['publicKey']! as String,
    name: json['name']! as String,
    platform: json['platform']! as String,
  );

  final String deviceId;
  final String privateKey;
  final String publicKey;
  final String name;
  final String platform;

  JsonMap toJson() => {
    'v': 1,
    'deviceId': deviceId,
    'privateKey': privateKey,
    'publicKey': publicKey,
    'name': name,
    'platform': platform,
  };
}

class _Credentials {
  _Credentials({
    required this.deviceId,
    required this.account,
    required this.accessToken,
    required this.accessTokenExpiresAt,
    required this.refreshToken,
    required this.refreshTokenExpiresAt,
    this.provider,
  });

  factory _Credentials.fromTokens(String deviceId, String account, DeviceTokenPair tokens, {String? provider}) =>
      _Credentials(
        deviceId: deviceId,
        account: account,
        accessToken: tokens.accessToken,
        accessTokenExpiresAt: tokens.accessTokenExpiresAt,
        refreshToken: tokens.refreshToken,
        refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
        provider: provider,
      );

  factory _Credentials.fromJson(JsonMap json) => _Credentials(
    deviceId: json['deviceId']! as String,
    account: json['account']! as String,
    accessToken: json['accessToken']! as String,
    accessTokenExpiresAt: DateTime.fromMillisecondsSinceEpoch(json['accessTokenExpiresAt']! as int),
    refreshToken: json['refreshToken']! as String,
    refreshTokenExpiresAt: DateTime.fromMillisecondsSinceEpoch(json['refreshTokenExpiresAt']! as int),
    provider: asString(json['provider']),
  );

  final String deviceId;
  final String account;
  final String accessToken;
  final DateTime accessTokenExpiresAt;
  final String refreshToken;
  final DateTime refreshTokenExpiresAt;

  /// Provider the device signed in with, when recorded.
  final String? provider;

  JsonMap toJson() => {
    'v': 1,
    'deviceId': deviceId,
    'account': account,
    'accessToken': accessToken,
    'accessTokenExpiresAt': accessTokenExpiresAt.millisecondsSinceEpoch,
    'refreshToken': refreshToken,
    'refreshTokenExpiresAt': refreshTokenExpiresAt.millisecondsSinceEpoch,
    'provider': ?provider,
  };
}

class _Pin {
  _Pin(this.identityKey, this.name, this.pinnedAt);
  final String identityKey;
  final String name;
  final DateTime pinnedAt;
}

/// One account on one ds-harness-remote Server.
///
/// ```dart
/// final account = RemoteAccount(secrets: MySecureStore());
/// if (await account.currentUser() == null) {
///   final login = await account.startLogin();          // or loginWithPassword
///   await launchUrl(login.loginUrl, mode: LaunchMode.externalApplication);
///   await login.result;
/// }
/// final hosts = await account.listHosts();
/// final client = await account.connectHost(hosts.first, onState: print);
/// final sessions = await client.listSessions();        // same DshClient API
/// ```
///
/// Everything secret (identity private key, access/refresh tokens, Host
/// pins) goes through [secrets], partitioned by Server origin. The account
/// web token from sign-in is used once to register this device and never
/// stored.
///
/// One Server connection per device: connecting to another Host closes the
/// previous remote client (the Server allows one Host connection per
/// client device).
class RemoteAccount {
  RemoteAccount({
    required SecretStore secrets,
    Object? serverUrl,
    this.deviceName = 'DSH App',
    this.platform = 'dsh-app-android',
    this.clientVersion = '0.1.0',
    HttpClient? httpClient,
    ControlSocketConnector? socketConnector,
    this.loginPollInterval = const Duration(seconds: 2),
    this.controlTracer,
    this.peerConnector,
    this.preferredTransports,
    this.onDirectFallback,
    this.compactHistory = false,
    this.directTimeout = const Duration(seconds: 8),
    this.iceServersTimeout = const Duration(seconds: 10),
  }) : serverUrl = normalizeServerUrl(serverUrl ?? defaultRemoteServer),
       _secrets = secrets,
       _socketConnector = socketConnector {
    api = RemoteServerApi(this.serverUrl, httpClient: httpClient);
    _scope = hashes.sha256.convert(utf8.encode(this.serverUrl.origin)).toString().substring(0, 24);
    final scopes = _accountStorageStates[secrets] ??= {};
    _storageState = scopes.putIfAbsent(_scope, _AccountStorageState.new);
  }

  final Uri serverUrl;
  final String deviceName;

  /// Device platform reported to the Server (`[a-z0-9][a-z0-9._-]*`).
  final String platform;
  final String clientVersion;
  final Duration loginPollInterval;

  /// Optional Control-frame tracer (tokens and ciphertext redacted).
  final ControlTracer? controlTracer;

  /// WebRTC stack for the direct path (LAN / P2P / TURN); `null` keeps every
  /// connection on the Relay. Read at each (re)connect, so a change applies
  /// from the next connection on.
  RemotePeerConnector? peerConnector;

  /// Optional native network hint. Actual selection still requires a working
  /// ICE pair. Exceptions or a stalled hint retain automatic defaults.
  Future<List<RemoteTransportMode>> Function()? preferredTransports;

  /// Payload-free fallback code ([RemoteNetworkFallbackReason.name]), never
  /// raw native exception text, SDP or candidate addresses.
  void Function(String reason)? onDirectFallback;

  /// Requests bounded history summaries from supporting Hosts. Captured by
  /// [connectHost] for that client's lifetime, including automatic reconnects.
  /// Changing it only affects the next [connectHost], not live streams or
  /// cached history. The first successful session fixes the effective mode:
  /// an unsupported Host stays full even if it gains support on reconnect.
  bool compactHistory;

  /// How long a direct attempt may take to open its DataChannel before the
  /// next path is tried (the Server's larger deadline is capped at 15 s).
  final Duration directTimeout;

  /// Budget for each connection's fresh STUN/TURN credential request,
  /// separate from the DataChannel negotiation deadline.
  final Duration iceServersTimeout;
  late final RemoteServerApi api;
  final SecretStore _secrets;
  final ControlSocketConnector? _socketConnector;
  late final String _scope;

  _Identity? _identity;
  Future<_Identity>? _creatingIdentity;
  _Credentials? _credentials;
  // Shared only within this storage object and normalized server scope.
  late final _AccountStorageState _storageState;
  bool _restored = false;
  Future<void>? _restoring;
  Map<String, _Pin>? _pins;
  ({_Credentials owner, Future<String> result})? _refreshing;
  _ActiveConnection? _active;
  final Map<String, DateTime> _directCooldown = {};
  final Map<String, DateTime> _turnCooldown = {};

  /// How long a path that just failed is skipped.
  ///
  /// The old 45 s was shorter than the app's own reconnect backoff, so the
  /// fallback chain was walked again and again. Ten minutes is long enough to
  /// cover the next few launches; a changed network still clears it (see
  /// the network hint below).
  static const transportCooldown = Duration(minutes: 10);
  final Map<String, String> _networkHints = {};
  final StreamController<RemoteConnectionState> _connectionStates = StreamController.broadcast();

  String get _identityKey => 'dsh_remote.v1.$_scope.identity';
  String get _credentialsKey => 'dsh_remote.v1.$_scope.credentials';
  String get _pinsKey => 'dsh_remote.v1.$_scope.pins';
  String get _cooldownsKey => 'dsh_remote.v1.$_scope.cooldowns';

  // ---------------------------------------------------------------------------
  // Account state

  /// The signed-in user, restoring stored credentials on first call; `null`
  /// when signed out or the refresh token expired.
  Future<RemoteUser?> currentUser() async {
    await _restore();
    final credentials = _credentials;
    if (credentials == null) return null;
    if (!credentials.refreshTokenExpiresAt.isAfter(DateTime.now().add(const Duration(seconds: 30)))) {
      return null;
    }
    return RemoteUser(
      account: credentials.account,
      deviceId: credentials.deviceId,
      serverUrl: serverUrl,
      provider: credentials.provider,
    );
  }

  Future<void> _restore() {
    if (_restored) return Future<void>.value();
    return _restoring ??= _readStoredAccount().whenComplete(() => _restoring = null);
  }

  Future<void> _readStoredAccount() async {
    final identity = asMap(tryDecodeJson(await _secrets.read(_identityKey) ?? ''));
    try {
      if (identity != null) _identity = _Identity.fromJson(identity);
    } on Object {
      _identity = null; // corrupt record: a new identity is created at sign-in
    }
    final credentials = asMap(tryDecodeJson(await _secrets.read(_credentialsKey) ?? ''));
    try {
      if (credentials != null) {
        final parsed = _Credentials.fromJson(credentials);
        if (parsed.deviceId == _identity?.deviceId) _credentials = parsed;
      }
    } on Object {
      _credentials = null;
    }
    _restored = true;
    await _loadCooldowns();
  }

  /// Reads the transport cooldowns and the network hint they were set under.
  ///
  /// The in-memory maps only live as long as the process: an App that the
  /// system killed starts the next launch knowing nothing about the paths
  /// that just failed, and walks the whole fallback chain again — a direct
  /// attempt that cannot work, a TURN attempt that cannot work, and only
  /// then the Relay that does. Persisting them means the next launch goes
  /// straight to what worked.
  Future<void> _loadCooldowns() async {
    try {
      final stored = asMap(tryDecodeJson(await _secrets.read(_cooldownsKey) ?? ''));
      if (stored == null) return;
      final now = DateTime.now();
      void read(String field, Map<String, DateTime> into) {
        final hosts = asMap(stored[field]);
        if (hosts == null) return;
        for (final entry in hosts.entries) {
          final at = DateTime.tryParse('${entry.value}');
          if (at != null && at.isAfter(now)) into[entry.key] = at;
        }
      }

      read('direct', _directCooldown);
      read('turn', _turnCooldown);
      final hints = asMap(stored['hint']);
      if (hints != null) {
        for (final entry in hints.entries) {
          final key = '${entry.value}';
          if (key.isNotEmpty) _networkHints[entry.key] = key;
        }
      }
    } on Object {
      // A missing or malformed store just means no cooldowns.
    }
  }

  /// Writes the cooldowns down. A hint that survives a restart is what lets
  /// the "the network changed, try the direct path again" rule work across
  /// process boundaries.
  Future<void> _saveCooldowns() async {
    try {
      final now = DateTime.now();
      String live(Map<String, DateTime> cooldowns) => jsonEncode({
        for (final entry in cooldowns.entries)
          if (entry.value.isAfter(now)) entry.key: entry.value.toIso8601String(),
      });
      await _secrets.write(
        _cooldownsKey,
        jsonEncode({'direct': live(_directCooldown), 'turn': live(_turnCooldown), 'hint': _networkHints}),
      );
    } on Object {
      // A hint that cannot be stored must never break a connection.
    }
  }

  /// QR-capable sign-in providers of this Server (empty on a self-hosted
  /// Server: use [loginWithPassword]).
  Future<List<OAuthProvider>> loginProviders() => _guard(() async {
    final providers = await api.oauthProviders();
    return providers.where((p) => p.supportsQrLogin).toList();
  });

  /// Starts a QR / browser sign-in with [providerId] (default: the first
  /// QR-capable provider). Works without any app URL scheme: the account
  /// authorizes in the browser, this device polls for the result.
  Future<RemoteLogin> startLogin({String? providerId}) => _guard(() async {
    final providers = await loginProviders();
    final provider = providerId == null
        ? (providers.isEmpty ? null : providers.first)
        : providers.where((p) => p.id == providerId).firstOrNull;
    if (provider == null) {
      throw const RemoteConnectException(
        RemoteFailure(
          'OAUTH_PROVIDER_UNAVAILABLE',
          'No QR sign-in provider is available on this Server.',
          retryable: false,
        ),
      );
    }
    final session = await api.startQrLogin(provider);
    final expiresAt = DateTime.now().add(session.expiresIn);
    final completer = Completer<RemoteUser>();
    var cancelled = false;
    var committing = false;
    const cancelledError = RemoteConnectException(
      RemoteFailure('LOGIN_CANCELLED', 'Sign-in was cancelled.', retryable: true),
    );
    void checkCancelled() {
      if (cancelled) throw cancelledError;
    }

    Future<void> poll() async {
      while (!cancelled && DateTime.now().isBefore(expiresAt)) {
        QrPollResult result;
        try {
          result = await api.pollQrLogin(session.qrId);
        } on RemoteApiException catch (error) {
          if (!error.retryable) rethrow;
          await Future<void>.delayed(loginPollInterval);
          continue;
        }
        if (cancelled) return;
        switch (result) {
          case QrComplete(:final accountToken):
            final account = await api.accountMe(accountToken);
            if (cancelled) return;
            final user = await _registerWithAccountToken(
              accountToken,
              account,
              provider: provider.id,
              checkCancelled: checkCancelled,
              beforeCommit: () {
                checkCancelled();
                committing = true;
              },
            );
            completer.complete(user);
            return;
          case QrExpired():
            throw const RemoteConnectException(
              RemoteFailure('LOGIN_EXPIRED', 'The sign-in session expired.', retryable: true),
            );
          case QrPending():
            await Future<void>.delayed(loginPollInterval);
        }
      }
      if (!cancelled) {
        throw const RemoteConnectException(
          RemoteFailure('LOGIN_EXPIRED', 'The sign-in session expired.', retryable: true),
        );
      }
    }

    unawaited(
      poll().catchError((Object error) {
        if (!completer.isCompleted) completer.completeError(_asConnectException(error));
      }),
    );
    return RemoteLogin._(session.scanUrl, provider.id, expiresAt, completer.future, () {
      if (committing || completer.isCompleted) return;
      cancelled = true;
      completer.completeError(cancelledError);
    });
  });

  /// Email/password sign-in (the self-hosted Server's only method; the
  /// hosted one supports it for invited accounts).
  Future<RemoteUser> loginWithPassword(String email, String password) => _guard(() async {
    final login = await api.loginWithPassword(email, password);
    return _registerWithAccountToken(login.token, login.account, provider: 'password');
  });

  Future<RemoteUser> _registerWithAccountToken(
    String accountToken,
    String account, {
    String? provider,
    void Function()? checkCancelled,
    void Function()? beforeCommit,
  }) async {
    await _restore();
    checkCancelled?.call();
    var identity = await _ensureIdentity();
    checkCancelled?.call();
    DeviceTokenPair tokens;
    try {
      tokens = await api.registerDevice(_descriptor(identity), accountToken);
    } on RemoteApiException catch (error) {
      checkCancelled?.call();
      // A revoked or conflicting identity is replaced; sign-in is the
      // explicit re-authorization boundary.
      if (error.code != 'DEVICE_REVOKED' && error.code != 'PEER_IDENTITY_MISMATCH') rethrow;
      identity = await _ensureIdentity(rotate: true);
      checkCancelled?.call();
      tokens = await api.registerDevice(_descriptor(identity), accountToken);
    }
    checkCancelled?.call();
    await _saveCredentials(
      _Credentials.fromTokens(identity.deviceId, account, tokens, provider: provider),
      beforeWrite: beforeCommit,
      signIn: true,
    );
    return RemoteUser(account: account, deviceId: identity.deviceId, serverUrl: serverUrl, provider: provider);
  }

  DeviceDescriptor _descriptor(_Identity identity) => DeviceDescriptor(
    deviceId: identity.deviceId,
    name: identity.name,
    role: 'client',
    platform: identity.platform,
    identityKey: identity.publicKey,
    clientVersion: clientVersion,
  );

  Future<_Identity> _ensureIdentity({bool rotate = false}) async {
    // A cancelled sign-in may still be writing the identity. Its retry must
    // wait for that local mutation, or a late credential delete can erase it.
    final pending = _creatingIdentity;
    if (pending != null) return pending;
    final existing = _identity;
    if (existing != null && !rotate) return existing;
    final creating = _creatingIdentity = _createIdentity();
    try {
      return await creating;
    } finally {
      _creatingIdentity = null;
    }
  }

  Future<_Identity> _createIdentity() async {
    final keys = X25519KeyPair.generate();
    final identity = _Identity(
      deviceId: uuidV7(),
      privateKey: keys.privateKeyBase64Url,
      publicKey: keys.publicKeyBase64Url,
      name: deviceName,
      platform: platform,
    );
    await _secrets.write(_identityKey, jsonEncode(identity.toJson()));
    _identity = identity;
    await _dropCredentials();
    return identity;
  }

  Future<void> _saveCredentials(_Credentials credentials, {void Function()? beforeWrite, bool signIn = false}) {
    // SecretStore writes are atomic, but not cancellable. Serialize commits
    // so a slow older write cannot finish after a newer login's write.
    final write = _storageState.credentialWrites.then((_) async {
      beforeWrite?.call();
      await _secrets.write(_credentialsKey, jsonEncode(credentials.toJson()));
      _credentials = credentials;
      if (signIn) _storageState.signInEpoch++;
    });
    _storageState.credentialWrites = write.catchError((Object _) {});
    return write;
  }

  /// Signs out: closes the active connection, revokes this device on the
  /// Server (best effort, when [revokeDevice]) and deletes its tokens. A
  /// revoked device identity is discarded too; Host pins are kept.
  /// A newer committed sign-in retires further cleanup from this logout;
  /// a revoke or storage delete already issued cannot be undone here.
  Future<void> logout({bool revokeDevice = true}) async {
    final epoch = _storageState.signInEpoch;
    bool isCurrent() => epoch == _storageState.signInEpoch;
    await _restore();
    if (!isCurrent()) return;
    await _active?.close();
    if (!isCurrent()) return;
    final credentials = _credentials;
    if (revokeDevice && credentials != null) {
      try {
        final token = await accessToken();
        if (!isCurrent()) return;
        await api.revokeSelf(token);
      } on Object {
        // Offline or already revoked: still sign out locally.
      }
    }
    await _dropCredentials(isCurrent: isCurrent);
    if (revokeDevice && isCurrent()) {
      _identity = null;
      await _secrets.delete(_identityKey);
    }
  }

  /// Forces a token rotation (normally automatic, 60 s before expiry).
  Future<void> refresh() => _guard(() => accessToken(forceRefresh: true));

  /// A valid device access token, refreshing it when it expires within a
  /// minute. Concurrent callers share one refresh (refresh tokens rotate and
  /// a reused one revokes the whole family). Throws
  /// [RemoteConnectException] `ACCOUNT_AUTH_REQUIRED` when signed out.
  Future<String> accessToken({bool forceRefresh = false}) async {
    await _restore();
    final credentials = _credentials;
    if (credentials == null) {
      throw const RemoteConnectException(
        RemoteFailure('ACCOUNT_AUTH_REQUIRED', 'Sign in to the remote Server first.', retryable: false),
      );
    }
    if (!forceRefresh && credentials.accessTokenExpiresAt.isAfter(DateTime.now().add(const Duration(seconds: 60)))) {
      return credentials.accessToken;
    }
    final refreshing = _refreshing;
    if (refreshing != null && identical(refreshing.owner, credentials)) return refreshing.result;
    late final Future<String> result;
    result = _rotate(credentials).whenComplete(() {
      if (identical(_refreshing?.result, result)) _refreshing = null;
    });
    _refreshing = (owner: credentials, result: result);
    return result;
  }

  Future<String> _rotate(_Credentials credentials) async {
    if (!credentials.refreshTokenExpiresAt.isAfter(DateTime.now())) {
      await _dropCredentials(owner: credentials);
      throw const RemoteConnectException(
        RemoteFailure('ACCOUNT_AUTH_REQUIRED', 'The device sign-in expired; sign in again.', retryable: false),
      );
    }
    try {
      final tokens = await api.refresh(credentials.deviceId, credentials.refreshToken);
      await _saveCredentials(
        _Credentials.fromTokens(credentials.deviceId, credentials.account, tokens, provider: credentials.provider),
        beforeWrite: () {
          if (!identical(_credentials, credentials)) {
            throw const RemoteConnectException(
              RemoteFailure('ACCOUNT_AUTH_REQUIRED', 'The device sign-in changed during refresh.', retryable: false),
            );
          }
        },
      );
      return tokens.accessToken;
    } on RemoteApiException catch (error) {
      if (error.retryable || error.code == 'CONNECTION_FAILED' || error.code == 'RATE_LIMITED') {
        throw RemoteConnectException(RemoteFailure(error.code, error.message, retryable: true));
      }
      await _dropCredentials(owner: credentials);
      throw RemoteConnectException(
        RemoteFailure(
          'ACCOUNT_AUTH_REQUIRED',
          'The Server refused the device token (${error.code}); sign in again.',
          retryable: false,
        ),
      );
    }
  }

  Future<void> _dropCredentials({_Credentials? owner, bool Function()? isCurrent}) {
    // Deletes share the commit queue; retired refreshes and logouts recheck
    // their owner at the point where the mutation would actually begin.
    final write = _storageState.credentialWrites.then((_) async {
      if (isCurrent != null && !isCurrent()) return;
      if (owner != null && !identical(_credentials, owner)) return;
      _credentials = null;
      await _secrets.delete(_credentialsKey);
    });
    _storageState.credentialWrites = write.catchError((Object _) {});
    return write;
  }

  // ---------------------------------------------------------------------------
  // Hosts and pins

  /// Hosts on this account with presence, versions and pin status. Fetches
  /// every Host's descriptor (identity key) in parallel.
  Future<List<RemoteHost>> listHosts() => _guard(() async {
    final listings = await _withToken(api.listHosts);
    final pins = await _loadPins();
    return Future.wait(
      listings.map((listing) async {
        final peer = await _withToken((token) => api.device(token, listing.deviceId));
        final pin = pins[listing.deviceId];
        final key = peer.role == 'host' && identityKeyPattern.hasMatch(peer.identityKey) ? peer.identityKey : null;
        final trust = key == null
            ? RemoteHostTrust.unknown
            : pin == null
            ? RemoteHostTrust.unpinned
            : pin.identityKey == key
            ? RemoteHostTrust.pinned
            : RemoteHostTrust.keyChanged;
        return RemoteHost(
          id: listing.deviceId,
          name: listing.name,
          platform: listing.platform,
          online: peer.online ?? listing.online,
          trust: trust,
          harnessVersion: listing.harnessVersion ?? peer.harnessVersion,
          pluginVersion: listing.clientVersion ?? peer.clientVersion,
          lastSeenAt: peer.lastSeenAt ?? listing.lastSeenAt,
          identityKey: key,
          pinnedIdentityKey: pin?.identityKey,
          membershipId: listing.membershipId,
        );
      }),
    );
  });

  /// Forgets a Host's pinned key, so the next connect trusts (or prompts
  /// for) the key the Server reports. Use after a legitimate Host reinstall.
  Future<void> forgetHost(String hostId) async {
    final pins = await _loadPins();
    if (pins.remove(hostId) != null) await _savePins(pins);
  }

  Future<Map<String, _Pin>> _loadPins() async {
    final cached = _pins;
    if (cached != null) return cached;
    final json = asMap(asMap(tryDecodeJson(await _secrets.read(_pinsKey) ?? ''))?['hosts']) ?? const {};
    final pins = <String, _Pin>{};
    json.forEach((id, raw) {
      final map = asMap(raw);
      final key = asString(map?['identityKey']);
      if (key == null) return;
      pins[id] = _Pin(
        key,
        asString(map!['name']) ?? '',
        DateTime.fromMillisecondsSinceEpoch(asInt(map['pinnedAt']) ?? 0),
      );
    });
    return _pins = pins;
  }

  Future<void> _savePins(Map<String, _Pin> pins) => _secrets.write(
    _pinsKey,
    jsonEncode({
      'v': 1,
      'hosts': {
        for (final MapEntry(:key, :value) in pins.entries)
          key: {
            'identityKey': value.identityKey,
            'name': value.name,
            'pinnedAt': value.pinnedAt.millisecondsSinceEpoch,
          },
      },
    }),
  );

  Future<T> _withToken<T>(Future<T> Function(String token) action) async {
    final token = await accessToken();
    try {
      return await action(token);
    } on RemoteApiException catch (error) {
      if (!error.isAuthFailure) rethrow;
      return action(await accessToken(forceRefresh: true));
    }
  }

  // ---------------------------------------------------------------------------
  // Connect

  /// Current state of the active remote connection.
  RemoteConnectionState? get connectionState => _active?.carrier.state;

  /// States of whichever Host connection is active (connecting / connected
  /// / reconnecting / failed / closed).
  Stream<RemoteConnectionState> get connectionStates => _connectionStates.stream;

  /// The client of the active connection, if any.
  DshClient? get activeClient => _active?.client;

  /// Connects to [host] with end-to-end Noise encryption, directly
  /// ([peerConnector]) or through the Server Relay, and returns a ready
  /// [DshClient] (first `$events` generation received). The client
  /// reconnects by itself after drops; [onState] and [connectionStates]
  /// report progress and failures.
  ///
  /// Trust: the Host's identity key is pinned on first connect (after
  /// [confirmNewHost] approves, when given) and must never change afterwards
  /// (`PEER_IDENTITY_MISMATCH`, fail closed).
  ///
  /// Throws [RemoteConnectException] when not ready within [timeout], or at
  /// once for terminal failures and `HOST_OFFLINE`.
  Future<DshClient> connectHost(
    RemoteHost host, {
    void Function(RemoteConnectionState state)? onState,
    HostTrustPrompt? confirmNewHost,
    MuxOptions muxOptions = const MuxOptions(),
    Duration timeout = const Duration(seconds: 30),
    Duration healthInterval = const Duration(seconds: 25),
    Duration healthTimeout = const Duration(seconds: 10),
    DshTracer? tracer,
  }) async {
    final historyMode = _HistoryMode(compactHistory);
    await _restore();
    final previous = _active;
    _active = null;
    await previous?.close();
    late final RemoteTunnelCarrier carrier;
    carrier = RemoteTunnelCarrier(
      hostId: host.id,
      open: (last) => _openHostSession(host, last, confirmNewHost, historyMode, () => carrier.isClosed),
      healthInterval: healthInterval,
      healthTimeout: healthTimeout,
      tracer: tracer,
    );
    final client = DshClient.withCarrier(carrier, muxOptions: muxOptions);
    final active = _ActiveConnection(client, carrier);
    _active = active;
    active.stateSub = carrier.states.listen((state) {
      onState?.call(state);
      if (_active == active && !_connectionStates.isClosed) _connectionStates.add(state);
      if (state.phase == RemoteConnectionPhase.closed && _active == active) _active = null;
    });
    carrier.attachMux(client.mux);

    final ready = client.mux.ready(timeout: timeout);
    final failFast = Completer<RemoteFailure>();
    final failSub = carrier.failures.listen((failure) {
      if (!failFast.isCompleted && (!failure.retryable || failure.code == 'HOST_OFFLINE')) {
        failFast.complete(failure);
      }
    });
    try {
      final outcome = await Future.any<Object?>([ready, failFast.future]);
      if (outcome is RemoteFailure) throw RemoteConnectException(outcome);
      return client;
    } on Object catch (error) {
      ready.ignore();
      if (_active == active) _active = null;
      await active.close();
      if (error is RemoteConnectException) rethrow;
      throw RemoteConnectException(
        carrier.lastFailure ??
            switch (error) {
              DshCarrierRefusedException(:final code, :final message) => RemoteFailure(code, message, retryable: false),
              _ => RemoteFailure('CONNECTION_FAILED', '$error', retryable: true),
            },
      );
    } finally {
      await failSub.cancel();
    }
  }

  Future<RemoteHostSession> _openHostSession(
    RemoteHost host,
    RemoteFailure? previous,
    HostTrustPrompt? confirm,
    _HistoryMode historyMode,
    bool Function() isCancelled,
  ) async {
    try {
      return await _openHostSessionOnce(host, previous, confirm, historyMode, isCancelled);
    } on RemoteConnectException {
      rethrow;
    } on Object catch (error) {
      throw _asConnectException(error);
    }
  }

  Future<RemoteHostSession> _openHostSessionOnce(
    RemoteHost host,
    RemoteFailure? previous,
    HostTrustPrompt? confirm,
    _HistoryMode historyMode,
    bool Function() isCancelled,
  ) async {
    final identity = _identity;
    if (identity == null || _credentials == null) {
      throw const RemoteConnectException(
        RemoteFailure('ACCOUNT_AUTH_REQUIRED', 'Sign in to the remote Server first.', retryable: false),
      );
    }
    final staleToken = previous?.code == 'TOKEN_EXPIRED' || previous?.code == 'AUTH_INVALID';
    var token = await accessToken(forceRefresh: staleToken);

    // 1. Authorized descriptor + pin check (fails closed before any socket).
    AuthorizedPeer peer;
    try {
      peer = await api.device(token, host.id);
    } on RemoteApiException catch (error) {
      if (!error.isAuthFailure) rethrow;
      token = await accessToken(forceRefresh: true);
      peer = await api.device(token, host.id);
    }
    if (peer.role != 'host' || peer.deviceId != host.id || !identityKeyPattern.hasMatch(peer.identityKey)) {
      throw const RemoteConnectException(
        RemoteFailure('INVALID_MESSAGE', 'The Server returned an invalid Host descriptor.', retryable: false),
      );
    }
    if (peer.online == false) {
      throw const RemoteConnectException(RemoteFailure('HOST_OFFLINE', 'The Host is offline.', retryable: true));
    }
    final hostKey = await _checkPin(host, peer, confirm);
    // Exclude a first-use trust prompt's human response time.
    final setup = Stopwatch()..start();

    // 2. Data plane: direct when enabled and negotiated, else the Relay
    // (refresh once when the token is refused).
    _TransportSelection selection;
    try {
      selection = await _connectTransport(token, host.id, isCancelled);
    } on RemoteTransportException catch (error) {
      if (error.code != 'AUTH_INVALID' && error.code != 'TOKEN_EXPIRED') rethrow;
      token = await accessToken(forceRefresh: true);
      selection = await _connectTransport(token, host.id, isCancelled);
    }
    final transport = selection.transport;

    // 3. Noise IK (client = initiator) against the pinned key.
    final channel = await SecureChannel.establish(
      transport: transport,
      clientDeviceId: identity.deviceId,
      clientPrivateKey: identity.privateKey,
      clientPublicKey: identity.publicKey,
      hostDeviceId: host.id,
      hostIdentityKey: hostKey,
    );
    final rpc = RemoteRpcClient(channel);
    // A failed live carrier needs a fresh Noise session on a different path.
    // Cooldowns are short, account-local hints; no candidate or token is kept.
    unawaited(
      rpc.done.then((reason) {
        if (!reason.retryable || reason.code == 'CLIENT_CLOSED') return;
        final until = DateTime.now().add(transportCooldown);
        switch (transport is WebRtcTransport ? transport.actualMode ?? transport.mode : transport.mode) {
          case RemoteTransportMode.lan || RemoteTransportMode.p2p:
            _directCooldown[host.id] = until;
          case RemoteTransportMode.turn:
            _directCooldown[host.id] = until;
            _turnCooldown[host.id] = until;
          case RemoteTransportMode.relay:
            break;
        }
        unawaited(_saveCooldowns());
      }),
    );

    // 4. Capability probe: the first RPC must be harness.transport.describe.
    var probingCapabilities = true;
    try {
      final description = asMap(
        await rpc.call('harness.transport.describe', const <String, Object?>{}, timeout: const Duration(seconds: 10)),
      );
      probingCapabilities = false;
      final raw = description?['capabilities'];
      if (raw is! List ||
          raw.length > maxRemoteCapabilityEntries ||
          raw.any((c) => c is! String || c.isEmpty) ||
          raw.toSet().length != raw.length) {
        throw const RemoteConnectException(
          RemoteFailure('INVALID_MESSAGE', 'The Host returned invalid transport capabilities.', retryable: false),
        );
      }
      final capabilities = raw.cast<String>();
      final v3 = capabilities.contains('harness.remote.v3');
      final v1 = capabilities.contains('harness.remote.v1');
      if (v3 && v1) {
        throw const RemoteConnectException(
          RemoteFailure(
            'INVALID_MESSAGE',
            'The Host advertised conflicting Harness Session formats.',
            retryable: false,
          ),
        );
      }
      if (!v3) {
        throw RemoteConnectException(
          RemoteFailure(
            'HARNESS_VERSION_INCOMPATIBLE',
            v1
                ? 'The Host runs a pre-0.1.5 DSH (Session format v1); this client needs DSH 0.2.x (Session V3).'
                : 'The Host exposes no Typert Remote carrier (harness.remote.v3); update its ds-harness-remote plugin.',
            retryable: false,
          ),
        );
      }
      final supportsCompact = capabilities.contains('remote.history.compact.v1');
      final compact = historyMode.negotiated ?? (supportsCompact && historyMode.requested);
      if (compact && !supportsCompact) {
        throw const RemoteConnectException(
          RemoteFailure(
            'HISTORY_MODE_CHANGED',
            'The Host no longer supports compact history; create a new client to load full history.',
            retryable: false,
          ),
        );
      }
      if (supportsCompact) {
        final result = asMap(
          await rpc.call('remote.history.configure', {'compact': compact}, timeout: const Duration(seconds: 10)),
        );
        if (result == null || result.length != 1 || result['compact'] is! bool || result['compact'] != compact) {
          throw const RemoteConnectException(
            RemoteFailure('INVALID_MESSAGE', 'The Host returned an invalid history configuration.', retryable: false),
          );
        }
      }
      historyMode.negotiated = compact;
      setup.stop();
      RemoteNetworkDiagnostics snapshot() => RemoteNetworkDiagnostics(
        transportMode: transport is WebRtcTransport ? transport.actualMode : transport.mode,
        connectionDuration: setup.elapsed,
        roundTripTime: transport is WebRtcTransport ? transport.roundTripTime : null,
        peerNetwork: transport is WebRtcTransport ? transport.peerNetwork : null,
        fallbackReason:
            selection.fallbackReason ??
            (transport is WebRtcTransport && transport.actualMode == null
                ? RemoteNetworkFallbackReason.pathUnverified
                : null),
        observedAt: DateTime.now(),
      );
      return RemoteHostSession(
        rpc: rpc,
        // api.device was fetched and pin-checked for this exact opening.
        // Do not fall back to host.harnessVersion (a stale listing).
        harnessVersion: peer.harnessVersion,
        capabilities: List.unmodifiable(capabilities),
        workspaceTypes: description!['workspaceTypes'],
        transport: transport.mode.name,
        networkDiagnostics: snapshot(),
        inspectNetwork: () async {
          if (transport is WebRtcTransport) await transport.inspectNetwork();
          return snapshot();
        },
      );
    } on RemoteRpcException catch (error) {
      await rpc.close();
      if (probingCapabilities && error.code == 'METHOD_NOT_FOUND') {
        throw const RemoteConnectException(
          RemoteFailure(
            'HARNESS_VERSION_INCOMPATIBLE',
            'The Host plugin predates capability discovery (rc.2 ApiProxy only); update ds-harness-remote on the Host.',
            retryable: false,
          ),
        );
      }
      throw RemoteConnectException(
        RemoteFailure(error.code, error.message, retryable: error.retryable || error.isLocal),
      );
    } on Object {
      await rpc.close();
      rethrow;
    }
  }

  /// Tries LAN/P2P without relay candidates, then TURN with relay-only ICE,
  /// then the Relay. Each failed stage gets a fresh authorized connection:
  /// the Host may still hold state for the old one. Noise always starts only
  /// after the final data plane is chosen. Recent failures skip the bad path
  /// for 45 seconds; a changed native network hint clears that cooldown.
  Future<_TransportSelection> _connectTransport(String token, String hostId, bool Function() isCancelled) async {
    final connector = peerConnector;
    if (connector == null) {
      return _TransportSelection(
        await _connectRelay(token, hostId, isCancelled: isCancelled),
        RemoteNetworkFallbackReason.webrtcUnavailable,
      );
    }
    var preferred = RemoteTransportMode.values;
    try {
      final hint = preferredTransports;
      if (hint != null) preferred = (await hint().timeout(const Duration(milliseconds: 500))).toSet().toList();
    } on Object {
      // Native connectivity can be unavailable during startup.
    }
    preferred = [...preferred.where((p) => p != RemoteTransportMode.relay), RemoteTransportMode.relay];
    final hintKey = preferred.map((p) => p.name).join(',');
    final oldHint = _networkHints[hostId];
    _networkHints[hostId] = hintKey;
    if (oldHint != null && oldHint != hintKey) {
      _directCooldown.remove(hostId);
      _turnCooldown.remove(hostId);
      unawaited(_saveCooldowns());
    }
    final now = DateTime.now();
    final skipDirect = _directCooldown[hostId]?.isAfter(now) ?? false;
    final skipTurn = _turnCooldown[hostId]?.isAfter(now) ?? false;
    RemoteNetworkFallbackReason? reason = skipDirect ? RemoteNetworkFallbackReason.directRecentlyFailed : null;
    var wantDirect = !skipDirect && preferred.any((p) => p == RemoteTransportMode.lan || p == RemoteTransportMode.p2p);
    var wantTurn = !skipTurn && preferred.contains(RemoteTransportMode.turn);
    // Credentials belong to a connectionId. A failed direct-stage lookup
    // must not suppress a fresh lookup on the separately authorized TURN stage.
    Future<List<RemoteIceServer>> fetchIce(String id) => api.turnCredentials(token, id);

    if (!wantDirect && !wantTurn) {
      return _TransportSelection(await _connectRelay(token, hostId, isCancelled: isCancelled), reason);
    }
    var control = await _connectRelay(token, hostId, direct: true, preferred: preferred, isCancelled: isCancelled);
    if (control.directTransports.isEmpty) {
      return _TransportSelection(control, RemoteNetworkFallbackReason.webrtcUnavailable);
    }
    wantDirect = wantDirect && control.directTransports.any((p) => p == 'lan' || p == 'p2p');
    wantTurn = wantTurn && control.directTransports.contains('turn');
    var directFailed = false;
    if (wantDirect) {
      try {
        final rtc = await WebRtcTransport.negotiate(
          control: control,
          connector: connector,
          iceServers: fetchIce,
          timeout: directTimeout,
          iceServersTimeout: iceServersTimeout,
        );
        return _TransportSelection(rtc, reason);
      } on WebRtcUnavailable catch (error) {
        directFailed = true;
        reason = error.timedOut ? RemoteNetworkFallbackReason.directTimeout : RemoteNetworkFallbackReason.directFailed;
        _directCooldown[hostId] = DateTime.now().add(transportCooldown);
        unawaited(_saveCooldowns());
        _notifyFallback(reason);
      }
      if (wantTurn) {
        control = await _connectRelay(token, hostId, direct: true, preferred: preferred, isCancelled: isCancelled);
      }
    }
    if (wantTurn) {
      try {
        final rtc = await WebRtcTransport.negotiate(
          control: control,
          connector: connector,
          iceServers: fetchIce,
          timeout: directTimeout,
          iceServersTimeout: iceServersTimeout,
          relayOnly: true,
        );
        return _TransportSelection(rtc, reason);
      } on WebRtcUnavailable catch (error) {
        if (error.turnUnavailable) {
          reason ??= RemoteNetworkFallbackReason.turnUnavailable;
        } else {
          reason = error.timedOut ? RemoteNetworkFallbackReason.turnTimeout : RemoteNetworkFallbackReason.turnFailed;
        }
        _turnCooldown[hostId] = DateTime.now().add(transportCooldown);
        unawaited(_saveCooldowns());
        // Missing credentials should not duplicate the direct-stage reason.
        if (!error.turnUnavailable || !directFailed) {
          _notifyFallback(reason);
        }
      }
    } else if (!wantDirect) {
      await control.close();
    }
    return _TransportSelection(await _connectRelay(token, hostId, isCancelled: isCancelled), reason);
  }

  void _notifyFallback(RemoteNetworkFallbackReason reason) {
    try {
      onDirectFallback?.call(reason.name);
    } on Object {
      // Diagnostic consumers cannot prevent transport fallback.
    }
  }

  Future<RelayTransport> _connectRelay(
    String token,
    String hostId, {
    required bool Function() isCancelled,
    bool direct = false,
    List<RemoteTransportMode>? preferred,
  }) => RelayTransport.connect(
    url: controlSocketUrl(serverUrl),
    deviceId: _identity!.deviceId,
    accessToken: token,
    hostDeviceId: hostId,
    clientVersion: clientVersion,
    connector: _socketConnector,
    isCancelled: isCancelled,
    tracer: controlTracer,
    offerDirect: direct,
    preferredTransports: preferred,
  );

  Future<String> _checkPin(RemoteHost host, AuthorizedPeer peer, HostTrustPrompt? confirm) async {
    final pins = await _loadPins();
    final pinned = pins[host.id];
    if (pinned != null) {
      if (!constantTimeEquals(utf8.encode(pinned.identityKey), utf8.encode(peer.identityKey))) {
        throw RemoteConnectException(
          RemoteFailure(
            'PEER_IDENTITY_MISMATCH',
            'The identity key of Host "${host.name}" changed (pinned ${identityFingerprint(pinned.identityKey)}, '
                'Server reports ${identityFingerprint(peer.identityKey)}). Refusing to connect.',
            retryable: false,
          ),
        );
      }
      return pinned.identityKey;
    }
    if (confirm != null) {
      final candidate = RemoteHost(
        id: host.id,
        name: peer.name,
        platform: peer.platform,
        online: peer.online ?? host.online,
        trust: RemoteHostTrust.unpinned,
        harnessVersion: peer.harnessVersion ?? host.harnessVersion,
        pluginVersion: peer.clientVersion ?? host.pluginVersion,
        lastSeenAt: peer.lastSeenAt,
        identityKey: peer.identityKey,
        membershipId: peer.membershipId,
      );
      if (!await confirm(candidate)) {
        throw const RemoteConnectException(
          RemoteFailure('HOST_NOT_TRUSTED', 'The new Host identity was not confirmed.', retryable: false),
        );
      }
    }
    pins[host.id] = _Pin(peer.identityKey, peer.name, DateTime.now());
    await _savePins(pins);
    return peer.identityKey;
  }

  /// Closes the active connection and the HTTP client.
  Future<void> close() async {
    await _active?.close();
    _active = null;
    await _connectionStates.close();
    api.close();
  }

  // ---------------------------------------------------------------------------

  Future<T> _guard<T>(Future<T> Function() action) async {
    try {
      return await action();
    } on RemoteConnectException {
      rethrow;
    } on Object catch (error) {
      throw _asConnectException(error);
    }
  }
}

RemoteConnectException _asConnectException(Object error) => switch (error) {
  RemoteConnectException() => error,
  RemoteApiException(:final code, :final message, :final retryable) => RemoteConnectException(
    RemoteFailure(code, message, retryable: retryable || code == 'CONNECTION_FAILED' || code == 'HOST_OFFLINE'),
  ),
  RemoteTransportException(:final code, :final message, :final retryable) => RemoteConnectException(
    RemoteFailure(code, message, retryable: retryable && !_terminalCodes.contains(code)),
  ),
  SecureChannelException(:final code, :final message, :final retryable) => RemoteConnectException(
    RemoteFailure(code, message, retryable: retryable && !_terminalCodes.contains(code)),
  ),
  RemoteRpcException(:final code, :final message) => RemoteConnectException(
    RemoteFailure(code, message, retryable: true),
  ),
  NoiseSessionError(:final code, :final message) => RemoteConnectException(
    RemoteFailure(code, message, retryable: false),
  ),
  ArgumentError() => RemoteConnectException(RemoteFailure('INVALID_ARGUMENT', '$error', retryable: false)),
  _ => RemoteConnectException(RemoteFailure('CONNECTION_FAILED', '$error', retryable: true)),
};

const Set<String> _terminalCodes = {
  'CONNECTION_REPLACED',
  'CONNECTION_REJECTED',
  'PEER_IDENTITY_MISMATCH',
  'MEMBERSHIP_REQUIRED',
  'DEVICE_REVOKED',
  'DEVICE_NOT_FOUND',
  'CAPABILITY_NOT_SUPPORTED',
  'UNSUPPORTED_VERSION',
  'ACCOUNT_AUTH_REQUIRED',
};

// A client's transcript cache must not mix compact and full baselines.
class _HistoryMode {
  _HistoryMode(this.requested);

  final bool requested;
  bool? negotiated;
}

class _ActiveConnection {
  _ActiveConnection(this.client, this.carrier);

  final DshClient client;
  final RemoteTunnelCarrier carrier;
  StreamSubscription<RemoteConnectionState>? stateSub;
  bool _closed = false;

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await client.close();
    await Future<void>.delayed(Duration.zero);
    await stateSub?.cancel();
  }
}

class _TransportSelection {
  const _TransportSelection(this.transport, this.fallbackReason);
  final SecureHandshakeTransport transport;
  final RemoteNetworkFallbackReason? fallbackReason;
}
