import 'package:crypto/crypto.dart';
import 'dart:typed_data';

/// Represents a secure comparison result, similar to `subtle::Choice` in Rust.
/// Returns 1 if true, 0 if false, allowing for constant-time logic integration.
typedef Choice = int;

/// A prime-order subgroup of a base field (EC, prime-order field ...).
///
/// This abstract class defines the contract for the underlying prime order group.
/// [E] is the type of the Group Element (Point).
/// [S] is the type of the Scalar.
abstract class Group<E extends GroupElement<E, S>, S extends GroupScalar<S>> {
  // --- Configuration ---

  /// The byte length necessary to represent group elements.
  int get elementLength;

  /// The byte length necessary to represent scalars.
  int get scalarLength;

  // --- Hashing to Curve/Scalar ---

  /// Transforms a password/input and domain separation tag (DST) into a curve point.
  ///
  /// [input] is a list of byte arrays (equivalent to `&[&[u8]]`).
  /// [dst] is the Domain Separation Tag.
  ///
  /// Throws [FormatException] (or a custom InternalError) if inputs are invalid.
  E hashToCurve(HashFun H, Uint8List input, Uint8List dst);

  /// Hashes a slice of pseudo-random bytes to a scalar.
  ///
  /// Throws [FormatException] (or a custom InternalError) if inputs are invalid.
  S hashToScalar(HashFun H, Uint8List input, Uint8List dst);

  // --- Element Operations ---

  /// Get the base point (generator) for the group.
  E get baseElement;

  /// Returns the identity group element (neutral element).
  E identityElement();

  /// Returns `1` (true) if the element is equal to the identity element, `0` otherwise.
  Choice isIdentityElement(E elem) {
    return identityElement().constantTimeEquals(elem);
  }

  /// Serializes the group element to a byte array.
  Uint8List serializeElement(E elem);

  /// Return an element from its fixed-length bytes representation.
  ///
  /// Throws [FormatException] if the element is not a valid point on the group
  /// or is the identity element (depending on specific protocol requirements).
  E deserializeElement(Uint8List elementBits);

  // --- Scalar Operations ---

  /// Picks a scalar at random using a cryptographically secure RNG.
  ///
  /// In Dart, you typically pass `Random.secure()` from `dart:math`.
  S randomScalar();

  /// The multiplicative inverse of this scalar.
  S invertScalar(S scalar);

  /// Returns `1` (true) if the scalar is zero, `0` otherwise.
  Choice isZeroScalar(S scalar);

  /// Serializes a scalar to bytes.
  Uint8List serializeScalar(S scalar);

  /// Return a scalar from its fixed-length bytes representation.
  ///
  /// Throws [FormatException] if the scalar is zero or invalid.
  S deserializeScalar(Uint8List scalarBits);
}

/// The type of group elements (e.g., a Point on an Elliptic Curve).
///
/// Corresponds to `Self::Elem` in Rust.
abstract class GroupElement<E, S> {
  /// Constant-time equality check.
  Choice constantTimeEquals(E other);

  /// Group addition: `self + other`.
  E operator +(E other);

  /// Scalar multiplication: `self * scalar`.
  E operator *(S scalar);
}

/// The type of base field scalars.
///
/// Corresponds to `Self::Scalar` in Rust.
abstract class GroupScalar<S> {
  /// Constant-time equality check.
  Choice constantTimeEquals(S other);

  /// Scalar addition: `self + other`.
  S operator +(S other);

  /// Scalar subtraction: `self - other`.
  S operator -(S other);

  /// Scalar multiplication: `self * other`.
  S operator *(S other);
}

Uint8List expandMessageXMD(
  HashFun H,
  Uint8List msg,
  Uint8List DST,
  int lenInBytes,
) {
  // Get hash properties from the crypto package
  final bInBytes = H.outputLength;
  final sInBytes = H.blockSize; // Input block size (e.g., 64 for SHA-256)

  // 1. ell = ceil(len_in_bytes / b_in_bytes)
  final ell = (lenInBytes / bInBytes).ceil();

  // 2. ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
  if (ell > 255) {
    throw ArgumentError('Invalid: ell must be <= 255, but was $ell');
  }
  if (lenInBytes > 65535) {
    throw ArgumentError(
        'Invalid: len_in_bytes must be <= 65535, but was $lenInBytes');
  }
  if (DST.length > 255) {
    throw ArgumentError(
        'Invalid: DST length must be <= 255, but was ${DST.length}');
  }

  // 3. DST_prime = DST || I2OSP(len(DST), 1)
  final dstBuilder = BytesBuilder();
  dstBuilder.add(DST);
  dstBuilder.addByte(DST.length); // I2OSP(len(DST), 1)
  final dstPrime = dstBuilder.toBytes();
  // 4. Z_pad = I2OSP(0, s_in_bytes)
  final zPad = Uint8List(sInBytes);

  // 5. l_i_b_str = I2OSP(len_in_bytes, 2)
  // (Converts len_in_bytes to a 2-byte string, big-endian)
  final lIBData = ByteData(2);
  lIBData.setUint16(0, lenInBytes);
  final lIBStr = lIBData.buffer.asUint8List();

  // 6. msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
  final msgPrimeBuilder = BytesBuilder();
  msgPrimeBuilder.add(zPad);
  msgPrimeBuilder.add(msg);
  msgPrimeBuilder.add(lIBStr);
  msgPrimeBuilder.addByte(0); // I2OSP(0, 1)
  msgPrimeBuilder.add(dstPrime);
  final msgPrime = msgPrimeBuilder.toBytes();

  // 7. b_0 = H(msg_prime)
  final b_0 = Uint8List.fromList(H.hash(msgPrime).bytes);

  // 8. b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  final biBuilder = BytesBuilder();
  biBuilder.add(b_0);
  biBuilder.addByte(1); // I2OSP(1, 1)
  biBuilder.add(dstPrime);
  final b_1 = Uint8List.fromList(H.hash(biBuilder.takeBytes()).bytes);

  // --- Steps 9, 10, 11 (Loop and concatenate) ---
  final uniformBytesBuilder = BytesBuilder();
  uniformBytesBuilder.add(b_1); // Add b_1

  Uint8List bPrev = b_1;

  for (int i = 2; i <= ell; i++) {
    // 10. b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    final xorResult = _strxor(b_0, bPrev);

    //final biBuilder = BytesBuilder();
    biBuilder.add(xorResult);
    biBuilder.addByte(i); // I2OSP(i, 1)
    biBuilder.add(dstPrime);

    final bI = Uint8List.fromList(H.hash(biBuilder.takeBytes()).bytes);

    uniformBytesBuilder.add(bI); // 11. uniform_bytes = b_1 || ...
    bPrev = bI; // Update for the next iteration
  }

  // 11. uniform_bytes = b_1 || ... || b_ell
  final uniformBytesFull = uniformBytesBuilder.toBytes();

  // 12. return substr(uniform_bytes, 0, len_in_bytes)
  // We use a view to avoid an unnecessary copy
  return Uint8List.view(uniformBytesFull.buffer, 0, lenInBytes);
}

/// Helper function to perform byte-wise XOR on two [Uint8List]s.
_strxor(Uint8List a, Uint8List b) {
  final result = Uint8List(a.length);
  for (int i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

abstract class HashFun {
  const HashFun();

  int get blockSize;
  int get outputLength;

  Digest hash(List<int> input);
}

class _Sha512fn extends HashFun {
  const _Sha512fn._();
  @override
  final int blockSize = 128;
  @override
  final int outputLength = 64;

  @override
  Digest hash(List<int> input) {
    var r = sha512.convert(input);
    return r;
  }
}

const HashFun Sha512fn = _Sha512fn._();
