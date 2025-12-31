import 'package:voprf/src/group/group.dart';

abstract class CipherSuite<G extends Group<GE, S>,
    GE extends GroupElement<GE, S>, S extends GroupScalar<S>> {
  /// The ciphersuite identifier as dictated by RFC 9497.
  String get id;

  /// Accessor for the Group logic.

  G get group;

  /// Accessor or Factory for the Hash logic.

  HashFun get hash;

  const CipherSuite();
}
