package demo.sasl.did;

import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class SaslDidServer extends SaslDidBase implements SaslServer {

    public SaslDidServer() {
        super();
    }

    @Override
    public byte[] evaluateResponse(byte[] bytes) throws SaslException {
        return new byte[0];
    }

    @Override
    public String getAuthorizationID() {
        return "";
    }

    @Override
    public void dispose() throws SaslException {

    }
}