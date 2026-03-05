package sasl.mechanism.did.client.did;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.PrivateKeySignerFactory;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import foundation.identity.did.DID;
import io.leonard.Base58;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.util.JWSAlgorithmUtil;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class DIDResponseGenerator {

    private static final Logger log = LogManager.getLogger(DIDResponseGenerator.class);

    public static String generateResponse(String challenge, DID did, JWK privateKeyJwk) throws GeneralSecurityException {
        byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);

        KeyTypeName keyTypeName = KeyTypeName_for_JWK.keyTypeName_for_JWK(privateKeyJwk);
        String algorithm = JWSAlgorithmUtil.getDefaultJWSAlgorithmForKeyTypeName(keyTypeName);
        PrivateKeySigner<?> privateKeySigner = PrivateKeySignerFactory.privateKeySignerForKey(privateKeyJwk, algorithm);

        byte[] signatureValue = privateKeySigner.sign(challengeBytes, algorithm);
        String signature = Base58.encode(signatureValue);

        String response = did + " " + signature;
        log.debug("Generated response for challenge {}: {}", challenge, response);
        return response;
    }
}
