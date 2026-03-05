package sasl.mechanism.did.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.DIDChallengeSaslBase;
import sasl.mechanism.did.messages.SASLChallenge;
import sasl.mechanism.did.server.did.DIDChallengeGenerator;
import sasl.mechanism.did.server.did.DIDResponseVerifier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class DIDChallengeSaslServer extends DIDChallengeSaslBase implements SaslServer {

    private static final Logger log = LogManager.getLogger(DIDChallengeSaslServer.class);

    private final String serverName;
    private final CallbackHandler cbh;

    private SASLChallenge challenge = null;
    private String authorizationId = null;

    public DIDChallengeSaslServer(String protocol, String serverName, Map<String,?> props, CallbackHandler cbh) throws SaslException {
        super();
        if (serverName == null) throw new SaslException("No 'serverName' specified");
        this.serverName = serverName;
        this.cbh = cbh;
    }

    @Override
    public byte[] evaluateResponse(byte[] responseData) throws SaslException {
        if (this.completed) throw new IllegalStateException("SASL authentication already completed");
        if (this.aborted) throw new IllegalStateException("SASL authentication aborted");

        if (this.challenge == null) {
            if (responseData.length != 0) {
                this.aborted = true;
                throw new SaslException("SASL mechanism does not expect any initial response");
            }
            return this.evaluateResponseForEmptyChallenge();
        } else {
            return this.evaluateResponseForChallenge(responseData);
        }
    }

    @Override
    public String getAuthorizationID() {
        if (! this.completed) throw new IllegalStateException("SASL authentication not completed");
        String result = this.authorizationId;
        log.info("getAuthorizationID() -> " + result);
        return result;
    }

    @Override
    public void dispose() throws SaslException {

    }

    private byte[] evaluateResponseForEmptyChallenge() throws SaslException {
        this.challenge = DIDChallengeGenerator.generateChallenge(this.serverName);
        log.debug("Generated challenge: {}", this.challenge);
        byte[] challengeData = this.challenge.getMessageBytes();
        return challengeData.clone();
    }

    private byte[] evaluateResponseForChallenge(byte[] responseBytes) throws SaslException {
        log.debug("Received response: {}", new String(responseBytes, StandardCharsets.UTF_8));

        String response = new String(responseBytes, StandardCharsets.UTF_8);
        int didLength = response.indexOf(' ');
        if (didLength == 0) {
            this.aborted = true;
            throw new SaslException("SASL: Invalid response; no DID found");
        }

        String did = response.substring(0, didLength);
        String signature = response.substring(didLength + 1);
        log.info("Extracted DID: {}", did);
        log.info("Extracted signature: {}", signature);

        NameCallback ncb = new NameCallback("Server DID: ", did);
        try {
            this.cbh.handle(new Callback[] { ncb });
        } catch (IOException | UnsupportedCallbackException ex) {
            this.aborted = true;
            throw new SaslException("SASL authentication failed", ex);
        }

        try {
            DIDResponseVerifier.verifySignature(this.challenge.getMessageBytes(), did, signature);
        } catch (Exception ex) {
            this.aborted = true;
            throw new SaslException("Failed to verify signature: " + ex.getMessage(), ex);
        }

        AuthorizeCallback acb = new AuthorizeCallback(did, did);
        try {
            this.cbh.handle(new Callback[] { acb });
        } catch (IOException | UnsupportedCallbackException ex) {
            this.aborted = true;
            throw new SaslException("SASL: authentication failed", ex);
        }

        if (acb.isAuthorized()) {
            this.authorizationId = acb.getAuthorizedID();
            log.debug("authorizationId: {}", this.authorizationId);
            this.completed = true;
            return null;
        } else {
            this.aborted = true;
            throw new SaslException("SASL: user not authorized: " + did);
        }
    }
}
