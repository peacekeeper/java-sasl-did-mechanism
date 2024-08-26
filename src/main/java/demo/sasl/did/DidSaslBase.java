package demo.sasl.did;

import javax.security.sasl.SaslException;

public abstract class DidSaslBase {

    protected boolean completed;
    protected boolean aborted;

    public DidSaslBase() {
        this.completed = false;
        this.aborted = false;
    }

    public String getMechanismName() {
        return DidSaslProvider.MECHANISM_NAME;
    }

    public boolean isComplete() {
        return this.completed;
    }

    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (this.completed) {
            throw new IllegalStateException("Not supported");
        } else {
            throw new IllegalStateException("Authentication not completed");
        }
    }

    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (this.completed) {
            throw new IllegalStateException("Not supported");
        } else {
            throw new IllegalStateException("Authentication not completed");
        }
    }

    public Object getNegotiatedProperty(String propName) {
        if (this.completed) {
            return null;
        } else {
            throw new IllegalStateException("CRAM-MD5 authentication not completed");
        }
    }
}