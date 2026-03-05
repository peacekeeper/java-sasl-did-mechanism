package sasl.mechanism.did.client.did;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.PrivateKeySignerFactory;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import foundation.identity.did.DID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.messages.DIDChallenge;
import sasl.mechanism.did.messages.DIDResponse;
import sasl.mechanism.did.util.JWSAlgorithmUtil;

import java.security.GeneralSecurityException;

public class DIDResponseGenerator {

    private static final Logger log = LogManager.getLogger(DIDResponseGenerator.class);

    public static DIDResponse generateResponse(DIDChallenge didChallenge, DID did, JWK privateKeyJwk) throws GeneralSecurityException {

        byte[] payload = didChallenge.getMessageBytes();

        KeyTypeName keyTypeName = KeyTypeName_for_JWK.keyTypeName_for_JWK(privateKeyJwk);
        String algorithm = JWSAlgorithmUtil.getDefaultJWSAlgorithmForKeyTypeName(keyTypeName);
        PrivateKeySigner<?> privateKeySigner = PrivateKeySignerFactory.privateKeySignerForKey(privateKeyJwk, algorithm);

        byte[] signatureValue = privateKeySigner.sign(payload, algorithm);

        DIDResponse didResponse = DIDResponse.create(did, signatureValue);
        log.debug("Generated response for challenge {}: {}", didChallenge, didResponse);
        return didResponse;
    }
}
