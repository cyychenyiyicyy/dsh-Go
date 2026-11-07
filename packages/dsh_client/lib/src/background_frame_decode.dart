/// Off-UI-isolate decoding for the `/api/remote.mux` WebSocket.
///
/// A remote conversation's opening snapshot is one WebSocket message of a
/// few megabytes: the whole loaded history in one JSON value. Decoding that
/// on the UI isolate is what froze the app — the frames simply stopped being
/// drawn while the main thread parsed it.
///
/// This runs the JSON decode in a worker isolate and hands the finished frame
/// back. The UI isolate then only walks the decoded map.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:isolate';

/// Frames above this size go to a worker. Small frames stay on the UI
/// isolate: a worker round trip costs more than parsing them.
const int backgroundFrameThresholdBytes = 64 * 1024;

/// Decodes one mux frame in a worker isolate.
///
/// Returns the decoded value, or null when the text is not JSON (the caller
/// treats that as a protocol failure, exactly as the inline path did).
Future<Object?> decodeFrameInWorker(String text) async {
  try {
    return await Isolate.run(() => jsonDecode(text));
  } on Object {
    // A worker that cannot start (or died) must not break the stream: the
    // caller falls back to reporting a protocol failure for this frame.
    return null;
  }
}
