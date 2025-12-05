package sasl.mechanism.did.client;

import com.danubetech.keyformats.jose.JWK;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.DIDChallengeSaslBase;
import sasl.mechanism.did.signatures.SignatureCreator;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class DIDChallengeSaslClient extends DIDChallengeSaslBase implements SaslClient {

    private static final Logger log = LogManager.getLogger(DIDChallengeSaslClient.class);

    private final String did;
    private JWK privateKey;

    public DIDChallengeSaslClient(String did, JWK privateKey) throws SaslException {
        if (did == null || privateKey == null) throw new SaslException("No 'authorizationId' or 'privateKey' specified");
        this.did = did;
        this.privateKey = privateKey;
    }

    @Override
    public boolean hasInitialResponse() {
        boolean result = false;
        log.info("hasInitialResponse() -> " + result);
        return result;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challengeData) throws SaslException {
        if (this.completed) throw new IllegalStateException("SASL authentication already completed");
        if (this.aborted) throw new IllegalStateException("SASL authentication already aborted");

        String challenge = new String(challengeData, StandardCharsets.UTF_8);
        log.debug("Received challenge: {}", challenge);

        String signature;
        try {
            signature = SignatureCreator.createSignature(challenge, this.privateKey);
        } catch (GeneralSecurityException ex) {
            throw new SaslException("Failed to create signature:" + ex.getMessage(), ex);
        }
        this.clearPrivateKey();

        String response = this.did + " " + signature;
        log.debug("Sending response: {}", response);

        this.completed = true;
        return response.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void dispose() {
        this.clearPrivateKey();
    }

    private void clearPrivateKey() {
        this.privateKey = null;
    }
}