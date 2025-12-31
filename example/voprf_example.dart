import 'package:voprf/voprf.dart';

void main() {
  final oprfClient = OprfClient<RistrettoCipherSuite, RistrettoGroup,
      RistrettoElement, RistrettoScalar>(
    RistrettoCipherSuite(),
  );
  print('OPRF Client created: $oprfClient');
}
