import 'dart:math';
import 'dart:typed_data';

import 'package:voprf/src/ciphersuite.dart';

import 'group.dart';

import 'package:ristretto255/ristretto255.dart';

class RistrettoScalar implements GroupScalar<RistrettoScalar> {
  final Scalar _scalar;

  RistrettoScalar(this._scalar);

  @override
  Choice constantTimeEquals(RistrettoScalar other) {
    return _scalar.equal(other._scalar);
  }

  @override
  RistrettoScalar operator +(RistrettoScalar other) {
    final res = Scalar();
    res.add(_scalar, other._scalar);
    return RistrettoScalar(res);
  }

  @override
  RistrettoScalar operator -(RistrettoScalar other) {
    final res = Scalar();
    res.subtract(_scalar, other._scalar);
    return RistrettoScalar(res);
  }

  @override
  RistrettoScalar operator *(RistrettoScalar other) {
    final res = Scalar();
    res.multiply(_scalar, other._scalar);
    return RistrettoScalar(res);
  }
}

class RistrettoElement
    implements GroupElement<RistrettoElement, RistrettoScalar> {
  final Element _element;

  RistrettoElement(this._element);

  @override
  Choice constantTimeEquals(RistrettoElement other) {
    return _element.equal(other._element);
  }

  @override
  RistrettoElement operator +(RistrettoElement other) {
    final res = Element.newIdentityElement();
    res.add(_element, other._element);
    return RistrettoElement(res);
  }

  @override
  RistrettoElement operator *(RistrettoScalar scalar) {
    final res = Element.newIdentityElement();
    res.scalarMult(scalar._scalar, _element);
    return RistrettoElement(res);
  }
}

class RistrettoGroup extends Group<RistrettoElement, RistrettoScalar> {
  @override
  int get elementLength => 32;

  @override
  int get scalarLength => 32;

  @override
  RistrettoElement identityElement() =>
      RistrettoElement(Element.newIdentityElement());

  @override
  Uint8List serializeElement(RistrettoElement elem) {
    return Uint8List.fromList(elem._element.encode());
  }

  @override
  RistrettoElement deserializeElement(Uint8List elementBits) {
    final elem = Element.newElement();
    try {
      elem.decode(elementBits);
    } catch (e) {
      throw FormatException('Invalid Ristretto element encoding: $e');
    }
    return RistrettoElement(elem);
  }

  @override
  RistrettoScalar randomScalar() {
    var randomBytes = Uint8List(scalarLength);
    final Random secureRandom = Random.secure();
    while (true) {
      try {
        for (var i = 0; i < randomBytes.length; i++) {
          // Fills each byte with a cryptographically secure random value
          randomBytes[i] = secureRandom.nextInt(256);
        }
        return deserializeScalar(randomBytes);
      } catch (_) {
        continue; // Invalid scalar encoding, try again.
      }
    }
  }

  @override
  RistrettoScalar invertScalar(RistrettoScalar scalar) {
    final res = Scalar();
    res.invert(scalar._scalar);
    return RistrettoScalar(res);
  }

  @override
  Choice isZeroScalar(RistrettoScalar scalar) {
    final zero = Scalar();
    zero.zero();
    return scalar._scalar.equal(zero);
  }

  @override
  Uint8List serializeScalar(RistrettoScalar scalar) {
    return Uint8List.fromList(scalar._scalar.encode());
  }

  @override
  RistrettoScalar deserializeScalar(Uint8List scalarBits) {
    final scalar = Scalar();
    scalar.decode(scalarBits);
    return RistrettoScalar(scalar);
  }

  @override
  RistrettoElement get baseElement {
    final base = Element.newGeneratorElement();
    return RistrettoElement(base);
  }

  @override
  RistrettoElement hashToCurve(HashFun H, Uint8List input, Uint8List dst) {
    final uniformBytes = expandMessageXMD(
      H,
      input,
      dst,
      64,
    );
    final elem = Element.newIdentityElement();
    try {
      elem.setUniformBytes(uniformBytes);
    } catch (e) {
      rethrow;
    }
    return RistrettoElement(elem);
  }

  @override
  RistrettoScalar hashToScalar(HashFun H, Uint8List input, Uint8List dst) {
    final uniformBytes = expandMessageXMD(
      H,
      input,
      dst,
      64,
    );
    final scalar = Scalar();
    try {
      scalar.setUniformBytes(uniformBytes);
    } catch (e) {
      rethrow;
    }
    return RistrettoScalar(scalar);
  }
}

class RistrettoCipherSuite
    extends CipherSuite<RistrettoGroup, RistrettoElement, RistrettoScalar> {
  @override
  String get id => 'ristretto255-SHA512';

  @override
  RistrettoGroup get group => RistrettoGroup();

  @override
  HashFun get hash => Sha512fn;

  const RistrettoCipherSuite();
}
