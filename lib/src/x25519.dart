import 'dart:typed_data';

final BigInt p = (BigInt.one << 255) - BigInt.from(19);
final BigInt a24 = BigInt.from(121665);
const int bits = 255;

BigInt mask(BigInt swap) {
  return BigInt.zero - swap;
}

({BigInt x2, BigInt x3}) cswap(BigInt swap, BigInt x2, BigInt x3) {
  BigInt m = mask(swap);
  BigInt dummy = m & (x2 ^ x3);
  x2 = x2 ^ dummy;
  x3 = x3 ^ dummy;
  return (x2: x2, x3: x3);
}

BigInt montgomeryLadder(BigInt k, BigInt u) {
  BigInt x1 = u;
  BigInt x2 = BigInt.one;
  BigInt z2 = BigInt.zero;
  BigInt x3 = u;
  BigInt z3 = BigInt.one;
  BigInt swap = BigInt.zero;

  for (int t = bits - 1; t >= 0; t--) {
    BigInt kt = (k >> t) & BigInt.one;
    swap ^= kt;

    ({BigInt x2, BigInt x3}) rx = cswap(swap, x2, x3);
    x2 = rx.x2;
    x3 = rx.x3;
    ({BigInt x2, BigInt x3}) rz = cswap(swap, z2, z3);
    z2 = rz.x2;
    z3 = rz.x3;
    swap = kt;

    BigInt a = (x2 + z2);
    a %= p;
    BigInt aa = (a * a);
    aa %= p;
    BigInt b = (x2 - z2);
    b %= p;
    BigInt bb = (b * b);
    bb %= p;
    BigInt e = (aa - bb);
    e %= p;
    BigInt c = (x3 + z3);
    c %= p;
    BigInt d = (x3 - z3);
    d %= p;
    BigInt da = (d * a);
    da %= p;
    BigInt cb = (c * b);
    cb %= p;

    x3 = (da + cb);
    x3 %= p;
    x3 = x3 * x3;
    x3 %= p;

    z3 = (da - cb);
    z3 %= p;
    z3 = z3 * z3;
    z3 %= p;
    z3 = z3 * x1;
    z3 %= p;

    x2 = (aa * bb);
    x2 %= p;

    z2 = (a24 * e);
    z2 %= p;
    z2 = (aa + z2);
    z2 %= p;
    z2 = (e * z2);
    z2 %= p;
  }

  ({BigInt x2, BigInt x3}) rx2 = cswap(swap, x2, x3);
  x2 = rx2.x2;
  x3 = rx2.x3;
  ({BigInt x2, BigInt x3}) rz2 = cswap(swap, z2, z3);
  z2 = rz2.x2;
  z3 = rz2.x3;

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

Uint8List encodeUCoordinate(BigInt u) {
  if (u.isNegative || u >= p) throw ArgumentError('u-coordinate must be within the field range');

  final Uint8List result = Uint8List(32);
  final BigInt mask = BigInt.from(0xff);
  for (int i = 0; i < 32; i++) {
    result[i] = (u >> (8 * i) & mask).toInt();
  }

  return result;
}

BigInt decodeScalar25519(Uint8List k) {
  if (k.length != 32) throw ArgumentError('Scalar must be 32 bytes for X25519');

  final Uint8List kList = Uint8List.fromList(k);

  // Clamping the scalar as per X25519 specifications
  kList[0] &= 248; // Clears the three least significant bits of the first byte
  kList[31] &= 127; // Clears the most significant bit of the last byte
  kList[31] |= 64; // Sets the second most significant bit of the last byte

  return decodeLittleEndian(kList);
}

Uint8List clamp(Uint8List r) {
  if (r.length != 32) throw ArgumentError('Input must be 32 bytes for clamping');

  r[0] &= 248;
  r[31] &= 127;
  r[31] |= 64;
  return r;
}

Uint8List x25519(Uint8List k, Uint8List u) {
  if (k.length != 32) throw ArgumentError('Scalar k must be 32 bytes');
  if (u.length != 32) throw ArgumentError('u-coordinate must be 32 bytes');

  final BigInt scalar = decodeScalar25519(k);
  final BigInt uCoordinate = decodeUCoordinate(u);
  final BigInt resultUCoordinate = montgomeryLadder(scalar, uCoordinate);

  return encodeUCoordinate(resultUCoordinate);
}
