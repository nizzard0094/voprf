import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:voprf/src/common.dart';
import 'package:voprf/src/group/group.dart';
import 'package:voprf/src/group/ristretto.dart';
import 'package:voprf/src/oprf.dart';
import 'package:test/test.dart';

void main() {
  test('expandMessageXMD', () {
    final input = Uint8List.fromList(utf8.encode('abcdef0123456789'));
    final result = expandMessageXMD(
        Sha512fn,
        input,
        Uint8List.fromList('QUUX-V01-CS02-with-expander-SHA512-256'.codeUnits),
        32);
    final String hexString = hex.encode(result);
    expect(
        hexString,
        equals(
            '087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58'));
  });

  group('Ristretto', () {
    final cipherSuite = RistrettoCipherSuite();

    // ignore: non_constant_identifier_names
    final skSm_bits = Uint8List.fromList(hex.decode(
        '5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e'));
    // ignore: unused_local_variable
    final skSm = cipherSuite.group.deserializeScalar(skSm_bits);
    final OprfServer<RistrettoCipherSuite, RistrettoGroup, RistrettoElement,
            RistrettoScalar> oprfServer =
        OprfServer<RistrettoCipherSuite, RistrettoGroup, RistrettoElement,
            RistrettoScalar>(cipherSuite, skSm);
    final OprfClient<RistrettoCipherSuite, RistrettoGroup, RistrettoElement,
            RistrettoScalar> oprfClient =
        OprfClient<RistrettoCipherSuite, RistrettoGroup, RistrettoElement,
            RistrettoScalar>(cipherSuite);
    final mode = Mode.oprf;
    test('oprf Ristretto', () {
      final input = Uint8List.fromList(hex.decode('00'));
      final blind_bits = Uint8List.fromList(hex.decode(
          '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'));
      final blind = cipherSuite.group.deserializeScalar(blind_bits);
      final blindedElement = deterministicBlindUnchecked<RistrettoCipherSuite,
          RistrettoGroup, RistrettoElement, RistrettoScalar>(
        cipherSuite,
        input,
        blind,
        mode,
      );
      final blindedElementBits =
          cipherSuite.group.serializeElement(blindedElement);
      final String hexString = hex.encode(blindedElementBits);
      expect(hexString,
          '609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c');
      final evaluatedElement = oprfServer.blindEvaluate(blindedElement);
      final evaluatedElementBits =
          cipherSuite.group.serializeElement(evaluatedElement);
      final String evalHexString = hex.encode(evaluatedElementBits);
      expect(evalHexString,
          '7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e');
      final output = oprfClient.finalize(input, blind, evaluatedElement);
      final String outputHexString = hex.encode(output);
      expect(outputHexString,
          '527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6');
    });
  });
}
