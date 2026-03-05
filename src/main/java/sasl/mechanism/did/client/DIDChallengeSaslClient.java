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

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.regex.Pattern;

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
    public byte[] evaluateChallenge(byte[] challengeData) throws SaslException {
        if (this.completed) throw new IllegalStateException("SASL authentication already completed");
        if (this.aborted) throw new IllegalStateException("SASL authentication already aborted");

        String challenge = new String(challengeData, StandardCharsets.UTF_8);
        log.debug("Received challenge: {}", challenge);

        String response;
        if (isDIDChallenge(challenge)) {
            try {
                response = DIDResponseGenerator.generateResponse(challenge, this.did, this.privateKey);
            } catch (GeneralSecurityException ex) {
                throw new SaslException("Failed to create DID Response:" + ex.getMessage(), ex);
            }
        } else if (isVCVPChallenge(challenge)) {
            try {
                response = VCVPResponseGenerator.generateResponse(challenge, this.did, this.privateKey, this.verifiableCredentials);
            } catch (GeneralSecurityException | JsonLDException | IOException ex) {
                throw new SaslException("Failed to create VC/VP Response:" + ex.getMessage(), ex);
            }
        } else {
            throw new SaslException("Challenge not supported: " + challenge);
        }

        this.completed = true;
        log.debug("Sending response: {}", response);
        return response.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void dispose() {
        this.clearPrivateData();
    }

    private void clearPrivateData() {
        this.privateKey = null;
        this.verifiableCredentials = null;
    }

    private static final Pattern PATTERN_DID_CHALLENGE = Pattern.compile("<([^.]+)\\.([^.]+)@([^.]+)>");
    private static final Pattern PATTERN_VCVP_CHALLENGE = Pattern.compile("<([^.]+)\\.([^.]+)\\.([^.]+)@([^.]+)>");

    private static boolean isDIDChallenge(String challenge) {
        return PATTERN_DID_CHALLENGE.matcher(challenge).matches();
    }

    private static boolean isVCVPChallenge(String challenge) {
        return PATTERN_VCVP_CHALLENGE.matcher(challenge).matches();
    }
}