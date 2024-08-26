package demo.sasl.did;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public class SaslDidClient extends SaslDidBase implements SaslClient {

    private final String authorizationId;
    private boolean complete;

    public SaslDidClient(String authorizationId) {
        this.authorizationId = authorizationId;
        this.complete = false;
    }

    @Override
    public boolean hasInitialResponse() {
        return false;
    }

    @Override
    public byte[] evaluateChallenge(byte[] bytes) throws SaslException {
        return new byte[0];
    }

    @Override
    public void dispose() throws SaslException {

    }
}