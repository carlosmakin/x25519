import 'dart:math';
import 'dart:typed_data';

/// X25519 Key Agreement Scheme (RFC 7748).
///
/// This class implements an asymmetric elliptic curve Diffie-Hellman (ECDH) key exchange using 256-bit keys.
/// X25519 is designed for establishing secure communication channels by enabling the generation and management
/// of private and public keys, crucial for computing shared secrets in cryptographic protocols.
abstract class X25519 {
  /// Generates a 32-byte private key for X25519 key exchange.
  /// The key is formatted as per X25519 specifications.
  static Uint8List generatePrivateKey() {
    final Random random = Random.secure();
    final Uint8List privateKey = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      privateKey[i] = random.nextInt(256);
    }
    return _clamp(privateKey);
  }

  /// Derives a 32-byte public key from the given X25519 private key.
  static Uint8List generatePublicKey(Uint8List privateKey) {
    final Uint8List basePoint = Uint8List(32)..[0] = 9;
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

final BigInt p = (BigInt.one << 255) - BigInt.from(19);
final BigInt a24 = BigInt.from(121665);

BigInt _montgomeryLadder(BigInt k, BigInt u) {
  final BigInt x1 = u;

  BigInt x2 = BigInt.one;
  BigInt z2 = BigInt.zero;
  BigInt x3 = u;
  BigInt z3 = BigInt.one;
  BigInt swap = BigInt.zero;

  BigInt a, aa, b, bb, e, c, d, da, cb;
  BigInt dummy, m;

  for (int t = 255 - 1; t >= 0; t--) {
    final BigInt kt = (k >> t) & BigInt.one;
    swap ^= kt;

    m = BigInt.zero - swap;

    dummy = m & (x2 ^ x3);
    x2 = x2 ^ dummy;
    x3 = x3 ^ dummy;

    dummy = m & (z2 ^ z3);
    z2 = z2 ^ dummy;
    z3 = z3 ^ dummy;

    swap = kt;

    a = (x2 + z2) % p;
    aa = (a * a) % p;
    b = (x2 - z2) % p;
    bb = (b * b) % p;
    e = (aa - bb) % p;
    c = (x3 + z3) % p;
    d = (x3 - z3) % p;
    da = (d * a) % p;
    cb = (c * b) % p;

    x3 = (da + cb) % p;
    x3 = (x3 * x3) % p;

    z3 = (da - cb) % p;
    z3 = (z3 * z3) % p;
    z3 = (z3 * x1) % p;

    x2 = (aa * bb) % p;

    z2 = (a24 * e) % p;
    z2 = (aa + z2) % p;
    z2 = (e * z2) % p;
  }

  m = BigInt.zero - swap;
  x2 = x2 ^ (m & (x2 ^ x3));
  z2 = z2 ^ (m & (z2 ^ z3));

  return (x2 * (z2.modPow(p - BigInt.two, p))) % p;
}

BigInt decodeLittleEndian(Uint8List b) {
  if (b.length != 32) throw ArgumentError('Byte array must be 32 bytes');

  BigInt result = BigInt.zero;
  for (int i = 0; i < 32; i++) {
    result += BigInt.from(b[i]) << (8 * i);
  }
  return result;
}

BigInt decodeUCoordinate(Uint8List u) {
  if (u.length != 32) throw ArgumentError('u-coordinate must be 32 bytes');

  u[31] &= 0x7f; // Masks the most significant bit in the final byte
  return decodeLittleEndian(u);
}

Uint8List _encodeUCoordinate(BigInt u) {
  if (u.isNegative || u >= p) throw ArgumentError('u-coordinate must be within the field range');

  final Uint8List result = Uint8List(32);
  final BigInt mask = BigInt.from(0xff);
  for (int i = 0; i < 32; i++) {
    result[i] = (u >> (8 * i) & mask).toInt();
  }

  return result;
}

BigInt _decodeScalar25519(Uint8List k) {
  if (k.length != 32) throw ArgumentError('Scalar must be 32 bytes for X25519');

  final Uint8List kList = Uint8List.fromList(k);

  // Clamping the scalar as per X25519 specifications
  kList[0] &= 248; // Clears the three least significant bits of the first byte
  kList[31] &= 127; // Clears the most significant bit of the last byte
  kList[31] |= 64; // Sets the second most significant bit of the last byte

  return decodeLittleEndian(kList);
}

Uint8List _clamp(Uint8List r) {
  if (r.length != 32) throw ArgumentError('Input must be 32 bytes for clamping');

  r[0] &= 248;
  r[31] &= 127;
  r[31] |= 64;
  return r;
}

Uint8List x25519(Uint8List k, Uint8List u) {
  if (k.length != 32) throw ArgumentError('Scalar k must be 32 bytes');
  if (u.length != 32) throw ArgumentError('u-coordinate must be 32 bytes');

  final BigInt scalar = _decodeScalar25519(k);
  final BigInt uCoordinate = decodeUCoordinate(u);
  final BigInt resultUCoordinate = _montgomeryLadder(scalar, uCoordinate);

  return _encodeUCoordinate(resultUCoordinate);
}
