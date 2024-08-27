package sasl.did.mechanism.client;

import sasl.did.mechanism.DidSaslBase;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class DidSaslClient extends DidSaslBase implements SaslClient {

    private static final Logger log = LogManager.getLogger(DidSaslClient.class);

    private final String did;
    private final byte[] privateKeyBytes;

    public DidSaslClient(String did, byte[] privateKeyBytes) throws SaslException {
        if (did == null || privateKeyBytes == null) throw new SaslException("No 'authorizationId' or 'privateKey' specified");
        this.did = did;
        this.privateKeyBytes = privateKeyBytes;
    }

    @Override
    public boolean hasInitialResponse() {
        return false;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challengeData) throws SaslException {
        if (this.completed) throw new IllegalStateException("SASL authentication already completed");
        if (this.aborted) throw new IllegalStateException("SASL authentication already aborted");

        String challenge = new String(challengeData, StandardCharsets.UTF_8);
        log.debug("Received challenge: {}", challenge);

        String signature;
        try {
            signature = SignatureCreator.createSignature(challenge, this.privateKeyBytes);
        } catch (GeneralSecurityException ex) {
            throw new SaslException("Failed to create signature:" + ex.getMessage(), ex);
        }
        this.clearPrivateKeyBytes();

        String response = this.did + " " + signature;
        log.debug("Sending response: {}", response);

        this.completed = true;
        return response.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void dispose() {
        this.clearPrivateKeyBytes();
    }

    private void clearPrivateKeyBytes() {
        Arrays.fill(this.privateKeyBytes, (byte) 0);
    }
}