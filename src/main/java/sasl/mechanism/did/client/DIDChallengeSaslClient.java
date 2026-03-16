package sasl.mechanism.did.client;

import com.danubetech.keyformats.jose.JWK;
import com.danubetech.verifiablecredentials.VerifiableCredentialV2;
import foundation.identity.did.DID;
import foundation.identity.jsonld.JsonLDException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.DIDChallengeSaslBase;
import sasl.mechanism.did.client.did.DIDResponseGenerator;
import sasl.mechanism.did.client.did.VCVPResponseGenerator;
import sasl.mechanism.did.messages.DIDChallenge;
import sasl.mechanism.did.messages.SASLChallenge;
import sasl.mechanism.did.messages.SASLResponse;
import sasl.mechanism.did.messages.VCVPChallenge;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;

public class DIDChallengeSaslClient extends DIDChallengeSaslBase implements SaslClient {

    private static final Logger log = LogManager.getLogger(DIDChallengeSaslClient.class);

    private final DID did;
    private JWK privateKey;
    private Map<String, VerifiableCredentialV2> verifiableCredentials;

    public DIDChallengeSaslClient(DID did, JWK privateKey, Map<String, VerifiableCredentialV2> verifiableCredentials) throws SaslException {
        if (did == null || privateKey == null) throw new SaslException("No 'authorizationId' or 'privateKey' specified");
        this.did = did;
        this.privateKey = privateKey;
        this.verifiableCredentials = verifiableCredentials;
    }

    @Override
    public boolean hasInitialResponse() {
        boolean result = false;
        log.info("hasInitialResponse() -> " + result);
        return result;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challengeBytes) throws SaslException {
        if (this.completed) throw new IllegalStateException("SASL authentication already completed");
        if (this.aborted) throw new IllegalStateException("SASL authentication already aborted");

        log.info("Received challenge: {}", new String(challengeBytes, StandardCharsets.UTF_8));
        SASLChallenge saslChallenge = SASLChallenge.fromMessage(challengeBytes);
        log.debug("Parsed challenge: {}", saslChallenge);

        SASLResponse response;
        if (saslChallenge instanceof DIDChallenge didChallenge) {
            try {
                response = DIDResponseGenerator.generateResponse(didChallenge, this.did, this.privateKey);
            } catch (GeneralSecurityException ex) {
                throw new SaslException("Failed to create DID Response:" + ex.getMessage(), ex);
            }
        } else if (saslChallenge instanceof VCVPChallenge vcvpChallenge) {
            try {
                response = VCVPResponseGenerator.generateResponse(vcvpChallenge, this.did, this.privateKey, this.verifiableCredentials);
            } catch (GeneralSecurityException | JsonLDException | IOException ex) {
                throw new SaslException("Failed to create VC/VP Response:" + ex.getMessage(), ex);
            }
        } else {
            throw new SaslException("Challenge not supported: " + saslChallenge);
        }

        this.completed = true;
        log.info("Sending response: {}", response);
        return response.getMessageBytes();
    }

    @Override
    public void dispose() {
        this.clearPrivateData();
    }

    private void clearPrivateData() {
        this.privateKey = null;
        this.verifiableCredentials = null;
    }
}