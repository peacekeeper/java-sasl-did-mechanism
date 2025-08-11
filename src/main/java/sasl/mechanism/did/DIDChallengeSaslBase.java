package sasl.mechanism.did;

import javax.security.sasl.SaslException;

public abstract class DIDChallengeSaslBase {

    protected boolean completed;
    protected boolean aborted;

    public DIDChallengeSaslBase() {
        this.completed = false;
        this.aborted = false;
    }

    public String getMechanismName() {
        return DIDChallengeSaslProvider.MECHANISM_NAME;
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