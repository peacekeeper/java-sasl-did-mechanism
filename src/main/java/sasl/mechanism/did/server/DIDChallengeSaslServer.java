package sasl.mechanism.did.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.DIDChallengeSaslBase;
import sasl.mechanism.did.messages.*;
import sasl.mechanism.did.server.did.DIDChallengeGenerator;
import sasl.mechanism.did.server.did.DIDResponseVerifier;
import sasl.mechanism.did.server.did.VCVPResponseVerifier;

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

    private SASLChallenge saslChallenge = null;
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

        if (this.saslChallenge == null) {
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
        this.saslChallenge = DIDChallengeGenerator.generateChallenge(this.serverName);
        log.debug("Generated challenge: {}", this.saslChallenge);
        byte[] challengeData = this.saslChallenge.getMessageBytes();
        return challengeData.clone();
    }

    private byte[] evaluateResponseForChallenge(byte[] responseBytes) throws SaslException {

        log.info("Received response: {}", new String(responseBytes, StandardCharsets.UTF_8));
        SASLResponse saslResponse = SASLResponse.fromMessage(responseBytes);
        log.debug("Parsed response: {}", saslChallenge);

        if (saslResponse instanceof DIDResponse didResponse) {

            NameCallback ncb = new NameCallback("Server DID: ", didResponse.getDid().getDidString());
            try {
                this.cbh.handle(new Callback[] { ncb });
            } catch (IOException | UnsupportedCallbackException ex) {
                this.aborted = true;
                throw new SaslException("SASL authentication failed", ex);
            }

            try {
                DIDResponseVerifier.verifyResponse((DIDChallenge) this.saslChallenge, didResponse);
            } catch (Exception ex) {
                this.aborted = true;
                throw new SaslException("Failed to verify DID response: " + ex.getMessage(), ex);
            }

            AuthorizeCallback acb = new AuthorizeCallback(didResponse.getDid().getDidString(), didResponse.getDid().getDidString());
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
                throw new SaslException("SASL: user not authorized: " + didResponse.getDid().getDidString());
            }
        } else if (saslResponse instanceof VCVPResponse vcvpResponse) {

            try {
                VCVPResponseVerifier.verifyResponse((VCVPChallenge) this.saslChallenge, vcvpResponse);
            } catch (Exception ex) {
                this.aborted = true;
                throw new SaslException("Failed to verify VC/VP response: " + ex.getMessage(), ex);
            }

            return null;
        } else {
            throw new SaslException("Response not supported: " + saslResponse);
        }
    }
}
