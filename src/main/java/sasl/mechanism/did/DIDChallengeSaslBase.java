package sasl.mechanism.did;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.server.DIDChallengeSaslServer;

import javax.security.sasl.SaslException;

public abstract class DIDChallengeSaslBase {

    private static final Logger log = LogManager.getLogger(DIDChallengeSaslBase.class);

    protected boolean completed;
    protected boolean aborted;

    public DIDChallengeSaslBase() {
        this.completed = false;
        this.aborted = false;
    }

    public String getMechanismName() {
        String result = DIDChallengeSaslProvider.MECHANISM_NAME;
        log.info("getMechanismName() -> " + result);
        return result;
    }

    public boolean isComplete() {
        boolean result = this.completed;
        log.info("isComplete() -> " + result);
        return result;
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