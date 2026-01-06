import 'dart:ffi';
import 'dart:typed_data';
import 'package:voprf/src/ciphersuite.dart';
import 'package:voprf/src/group/group.dart';

// ignore: non_constant_identifier_names
final Uint8List STR_OPRF = Uint8List.fromList('OPRFV1-'.codeUnits);
// ignore: non_constant_identifier_names
final Uint8List STR_HASH_TO_GROUP =
    Uint8List.fromList('HashToGroup-'.codeUnits);
// ignore: non_constant_identifier_names
final Uint8List STR_FINALIZE = Uint8List.fromList('Finalize'.codeUnits);
// ignore: non_constant_identifier_names
final Uint8List STR_DERIVE_KEYPAIR =
    Uint8List.fromList('DeriveKeyPair'.codeUnits);

enum Mode {
  /// Non-verifiable mode.
  oprf,

  /// Verifiable mode.
  voprf,

  /// Partially-oblivious mode.
  poprf;

  /// Mode as it is represented in a context string.
  /// Returns a standard Dart int (which acts as a u8).
  int toU8() {
    switch (this) {
      case Mode.oprf:
        return 0;
      case Mode.voprf:
        return 1;
      case Mode.poprf:
        return 2;
    }
  }
}

Uint8List createContextString(CipherSuite cipherSuite, Mode mode) {
  final stringBuilder = BytesBuilder();
  stringBuilder.add(STR_OPRF);
  stringBuilder.addByte(mode.toU8());
  stringBuilder.add('-'.codeUnits);
  stringBuilder.add(cipherSuite.id.codeUnits);
  return stringBuilder.toBytes();
}

deriveKey<CS extends CipherSuite<G, GE, S>, G extends Group<GE, S>,
    GE extends GroupElement<GE, S>, S extends GroupScalar<S>>(
  CS cipherSuite,
  Uint8List seed,
  Uint8List info,
  Mode mode,
) {
  final bytebuilder = BytesBuilder();
  bytebuilder.add(STR_DERIVE_KEYPAIR);
  bytebuilder.add(createContextString(cipherSuite, mode));
  final dst = bytebuilder.takeBytes();
  bytebuilder.add(seed);
  bytebuilder.add(i2osp(info.length, 2));
  bytebuilder.add(info);
  final deriveInput = bytebuilder.takeBytes();
  bytebuilder.add(deriveInput);
  bytebuilder.addByte(0);
  final input = bytebuilder.takeBytes();
  final input_last_index = input.length - 1;
  for (int i = 0; i < 256; i++) {
    input[input_last_index] = i;
    S skS = cipherSuite.group.hashToScalar(cipherSuite.hash, input, dst);
    if (cipherSuite.group.isZeroScalar(skS) == 0) {
      return skS;
    }
  }
  throw Exception('DeriveKeyError');
}

deriveKeyPair<CS extends CipherSuite<G, GE, S>, G extends Group<GE, S>,
    GE extends GroupElement<GE, S>, S extends GroupScalar<S>>(
  CS cipherSuite,
  Uint8List seed,
  Uint8List info,
  Mode mode,
) {
  final skS = deriveKey<CS, G, GE, S>(cipherSuite, seed, info, mode);
  final pkS = cipherSuite.group.baseElement * skS;
  return (skS, pkS);
}

GE deterministicBlindUnchecked<
    CS extends CipherSuite<G, GE, S>,
    G extends Group<GE, S>,
    GE extends GroupElement<GE, S>,
    S extends GroupScalar<S>>(
  CS cipherSuite,
  Uint8List input,
  S blind,
  Mode mode,
) {
  return hashToGroup<CS, G, GE, S>(cipherSuite, input, mode) * blind;
}

GE hashToGroup<CS extends CipherSuite<G, GE, S>, G extends Group<GE, S>,
    GE extends GroupElement<GE, S>, S extends GroupScalar<S>>(
  CS cipherSuite,
  Uint8List input,
  Mode mode,
) {
  final dst = BytesBuilder();
  dst.add(STR_HASH_TO_GROUP);
  dst.add(createContextString(cipherSuite, mode));
  final point = cipherSuite.group.hashToCurve(
    cipherSuite.hash,
    input,
    dst.toBytes(),
  );
  return point;
}

Uint8List i2osp(int value, int length) {
  if (value < 0 || value >= (1 << (8 * length))) {
    throw ArgumentError("Integer too large for byte array length");
  }
  final result = Uint8List(length);
  for (var i = length - 1; i >= 0; i--) {
    result[i] = value & 0xff;
    value >>= 8;
  }
  return result;
}
