import 'dart:typed_data';

import 'package:voprf/src/ciphersuite.dart';
import 'package:voprf/src/common.dart';
import 'package:voprf/src/group/group.dart';

class OprfClient<CS extends CipherSuite<G, GE, S>, G extends Group<GE, S>,
    GE extends GroupElement<GE, S>, S extends GroupScalar<S>> {
  // Implementation of OPRF client
  final mode = Mode.oprf;
  final CS cipherSuite;
  OprfClient(this.cipherSuite);

  BlindData<GE, S> blind(
    Uint8List input,
  ) {
    final blindFactor = cipherSuite.group.randomScalar();
    GE element = hashToGroup<CS, G, GE, S>(cipherSuite, input, mode);
    GE blindedElement = element * blindFactor;
    return BlindData(blindFactor, blindedElement);
  }

  Uint8List finalize(
    Uint8List input,
    S blindFactor,
    GE evaluatedElement,
  ) {
    GE N = evaluatedElement * cipherSuite.group.invertScalar(blindFactor);
    Uint8List unblindedElementBits = cipherSuite.group.serializeElement(N);
    final hashInput = BytesBuilder();
    hashInput.add(i2osp(input.length, 2));
    hashInput.add(input);
    hashInput.add(i2osp(unblindedElementBits.length, 2));
    hashInput.add(unblindedElementBits);
    hashInput.add(STR_FINALIZE);
    final output = cipherSuite.hash.hash(
      hashInput.toBytes(),
    );
    return Uint8List.fromList(output.bytes);
  }
}

class OprfServer<CS extends CipherSuite<G, GE, S>, G extends Group<GE, S>,
    GE extends GroupElement<GE, S>, S extends GroupScalar<S>> {
  // Implementation of OPRF server
  final S skS;
  final CS cipherSuite;
  OprfServer(this.cipherSuite, this.skS);

  GE blindEvaluate(GE blindedElement) {
    return blindedElement * skS;
  }
}
