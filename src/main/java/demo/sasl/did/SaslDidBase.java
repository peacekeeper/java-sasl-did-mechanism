package demo.sasl.did;

import javax.security.sasl.SaslException;

public abstract class SaslDidBase {

    protected boolean complete;

    public SaslDidBase() {
        this.complete = false;
    }

    public String getMechanismName() {
        return SaslDidMechanismProvider.MECHANISM_NAME;
    }

    public boolean isComplete() {
        return this.complete;
    }

    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (this.complete) {
            throw new IllegalStateException("Not supported");
        } else {
            throw new IllegalStateException("Authentication not completed");
        }
    }

    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (this.complete) {
            throw new IllegalStateException("Not supported");
        } else {
            throw new IllegalStateException("Authentication not completed");
        }
    }

    public Object getNegotiatedProperty(String propName) {
        if (this.complete) {
            return null;
        } else {
            throw new IllegalStateException("CRAM-MD5 authentication not completed");
        }
    }
}