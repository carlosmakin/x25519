import 'dart:typed_data';

Uint8List hexToBytes(String hex) {
  final int length = hex.length;
  final Uint8List bytes = Uint8List(length ~/ 2);
  for (int i = 0; i < length; i += 2) {
    bytes[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return bytes;
}
