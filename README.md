## X25519 🔐

### Overview

This Dart repository implements the X25519 key exchange algorithm as outlined in [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748). X25519 is an emerging, highly efficient key exchange method, increasingly gaining popularity for securely establishing shared secrets over insecure channels.

### X25519

X25519 uses elliptic curve cryptography for key agreement and is known for its high security and performance. It is highly recommended and widely adopted for key exchange in modern cryptographic protocols. It's a preferred choice in TLS 1.3 and is supported in many IPsec implementations.

#### Key Features:
- **Strong Security**: Resistant to many known types of cryptographic attacks.
- **Efficient Performance**: Optimized for fast computations, even on platforms without cryptographic hardware acceleration.
- **Simplicity**: Has a straightforward implementation with reduced risk of critical vulnerabilities.

#### Best Practices:
- Always generate fresh private keys using a cryptographically secure random number generator.
- Never reuse private keys and always verify public keys before use.

### Background and History

Developed by Daniel J. Bernstein, X25519 is an evolution in the field of elliptic curve cryptography, focusing on security, simplicity, and performance.

### RFC 7748

RFC 7748 serves as a comprehensive guide for the X25519 algorithm, detailing its implementation, usage, and security considerations. This standardization ensures consistent and secure usage across various cryptographic systems.

## Usage Examples

### Real-World Use Case: Secure Messaging

**Scenario**: Implementing end-to-end encrypted messaging using X25519.

```dart
import 'dart:typed_data';
import 'package:x25519_dart/x25519.dart';

Uint8List alicePrivateKey = X25519.generatePrivateKey();
Uint8List alicePublicKey = X25519.generatePublicKey(alicePrivateKey);

Uint8List bobPrivateKey = X25519.generatePrivateKey();
Uint8List bobPublicKey = X25519.generatePublicKey(bobPrivateKey);

Uint8List aliceSharedSecret = X25519.computeSharedSecret(alicePrivateKey, bobPublicKey);
Uint8List bobSharedSecret = X25519.computeSharedSecret(bobPrivateKey, alicePublicKey);

// aliceSharedSecret and bobSharedSecret can be used for encrypting messages.
```

### Real-World Use Case: Secure File Transfer

**Scenario**: Securing file transfer between two parties.

```dart
import 'dart:typed_data';
import 'package:x25519_dart/x25519.dart';

// Alice generates her keys
Uint8List alicePrivateKey = X25519.generatePrivateKey();
Uint8List alicePublicKey = X25519.generatePublicKey(alicePrivateKey);

// Bob uses Alice's public key to encrypt a file
Uint8List bobPrivateKey = X25519.generatePrivateKey();
Uint8List sharedSecret = X25519.computeSharedSecret(bobPrivateKey, alicePublicKey);

// Use sharedSecret to encrypt the file before sending to Alice
```

## Contribution

Contributions to improve the implementation, enhance security, and extend functionality are welcome. If you find any issues or have suggestions, please feel free to open an issue or submit a pull request.