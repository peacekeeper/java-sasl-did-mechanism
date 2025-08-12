package sasl.mechanism.did.signatures;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.util.Map;

public class JWSAlgorithms {

    static final Map<KeyTypeName, String> JWS_ALGORITHMS = Map.of(
            KeyTypeName.RSA, JWSAlgorithm.RS256,
            KeyTypeName.secp256k1, JWSAlgorithm.ES256K,
            KeyTypeName.Ed25519, JWSAlgorithm.EdDSA,
            KeyTypeName.P_256, JWSAlgorithm.ES256,
            KeyTypeName.P_384, JWSAlgorithm.ES384,
            KeyTypeName.P_521, JWSAlgorithm.ES512
    );
}
