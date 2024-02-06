import 'dart:typed_data';

import 'package:x25519/src/x25519.dart';
import 'utilities/hex.dart';
import 'package:test/test.dart';

void main() {
  group('X25519 RFC 7748', () {
    test('Test Vector 1', () {
      final Uint8List scalar =
          hexToBytes('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
      final Uint8List uCoord =
          hexToBytes('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
      final Uint8List expected =
          hexToBytes('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552');

      final Uint8List result = x25519(scalar, uCoord);
      expect(result, equals(expected));
    });

    test('Test Vector 2', () {
      final Uint8List scalar =
          hexToBytes('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d');
      final Uint8List uCoord =
          hexToBytes('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493');
      final Uint8List expected =
          hexToBytes('95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957');

      final Uint8List result = x25519(scalar, uCoord);
      expect(result, equals(expected));
    });

    test('After one iteration', () {
      Uint8List k = hexToBytes('0900000000000000000000000000000000000000000000000000000000000000');
      Uint8List u = Uint8List.fromList(k);
      Uint8List expected =
          hexToBytes('422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079');

      expect(x25519(k, u), equals(expected));
    });

    test('After 1,000 iterations', () {
      Uint8List k = hexToBytes('0900000000000000000000000000000000000000000000000000000000000000');
      Uint8List u = Uint8List.fromList(k);
      Uint8List expected =
          hexToBytes('684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51');
      for (int i = 0; i < 1000; i++) {
        Uint8List oldK = Uint8List.fromList(k);
        k = x25519(k, u);
        u = oldK;
      }

      expect(k, equals(expected));
    });

    test('After 1,000,000 iterations', () {
      Uint8List k = hexToBytes('0900000000000000000000000000000000000000000000000000000000000000');
      Uint8List u = Uint8List.fromList(k);
      Uint8List expected =
          hexToBytes('7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424');

      for (int i = 0; i < 1000000; i++) {
        if (i % 10000 == 0) print(i);
        Uint8List oldK = Uint8List.fromList(k);
        k = x25519(k, u);
        u = oldK;
      }
      expect(k, equals(expected));
    }, skip: true);

    test('Diffie-Hellman Key Exchange', () {
      final Uint8List alicesPrivateKey =
          hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
      final Uint8List expectedAlicesPublicKey =
          hexToBytes('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
      final Uint8List bobsPrivateKey =
          hexToBytes('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
      final Uint8List expectedBobsPublicKey =
          hexToBytes('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
      final Uint8List expectedSharedSecret =
          hexToBytes('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');

      final Uint8List alicesPublicKey = X25519.generatePublicKey(alicesPrivateKey);
      final Uint8List bobsPublicKey = X25519.generatePublicKey(bobsPrivateKey);

      final Uint8List alicesSharedSecret =
          X25519.computeSharedSecret(alicesPrivateKey, bobsPublicKey);
      final Uint8List bobsSharedSecret =
          X25519.computeSharedSecret(bobsPrivateKey, alicesPublicKey);

      expect(alicesPublicKey, equals(expectedAlicesPublicKey));
      expect(bobsPublicKey, equals(expectedBobsPublicKey));

      expect(alicesSharedSecret, equals(expectedSharedSecret));
      expect(bobsSharedSecret, equals(expectedSharedSecret));
      expect(alicesSharedSecret, equals(bobsSharedSecret));
    });
  });
}
