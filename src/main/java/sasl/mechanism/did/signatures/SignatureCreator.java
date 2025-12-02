package sasl.mechanism.did.signatures;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.PrivateKeySignerFactory;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import io.leonard.Base58;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class SignatureCreator {

    private static final Logger log = LogManager.getLogger(SignatureCreator.class);

    public static String createSignature(String challenge, JWK privateKeyJwk) throws GeneralSecurityException {
        byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);

        KeyTypeName keyTypeName = KeyTypeName_for_JWK.keyTypeName_for_JWK(privateKeyJwk);
        String algorithm = JWSAlgorithms.JWS_ALGORITHMS.get(keyTypeName);
        PrivateKeySigner<?> privateKeySigner = PrivateKeySignerFactory.privateKeySignerForKey(privateKeyJwk, algorithm);

        byte[] signatureValue = privateKeySigner.sign(challengeBytes, algorithm);
        String signature = Base58.encode(signatureValue);
        log.debug("Created signature for challenge {}: {}", challenge, signature);
        return signature;
    }
}
