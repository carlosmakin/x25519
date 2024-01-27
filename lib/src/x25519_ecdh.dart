import 'dart:math';
import 'dart:typed_data';

import 'package:x25519/src/x25519.dart';

/// Provides X25519 key generation and shared secret computation functions.
abstract class X25519 {
  /// Generates a 32-byte private key for X25519 key exchange.
  /// The key is formatted as per X25519 specifications.
  static Uint8List generatePrivateKey() {
    final Random random = Random.secure();
    final Uint8List privateKey = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      privateKey[i] = random.nextInt(256);
    }
    return clamp(privateKey);
  }

  /// Derives a 32-byte public key from the given X25519 private key.
  static Uint8List generatePublicKey(Uint8List privateKey) {
    final Uint8List basePoint = Uint8List.fromList(<int>[9] + List<int>.filled(31, 0));
    return x25519(privateKey, basePoint);
  }

  /// Computes the shared secret using the user's private key and another party's public key.
  static Uint8List computeSharedSecret(Uint8List privateKey, Uint8List publicKey) {
    return x25519(privateKey, publicKey);
  }

  /// Checks if the given private key is valid for X25519.
  static bool isValidPrivateKey(Uint8List privateKey) {
    if (privateKey.length != 32) return false;
    if ((privateKey[0] & 0x07) != 0) return false;
    if ((privateKey[31] & 0x80) != 0) return false;
    if ((privateKey[31] & 0x40) == 0) return false;
    return true;
  }

  /// Checks if the given public key is valid for X25519.
  static bool isValidPublicKey(Uint8List publicKey) {
    return publicKey.length == 32;
  }
}
