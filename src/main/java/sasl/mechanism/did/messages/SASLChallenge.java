package sasl.mechanism.did.messages;

import javax.security.sasl.SaslException;
import java.nio.charset.StandardCharsets;

public abstract class SASLChallenge extends SASLMessage {

    protected SASLChallenge(byte[] messageBytes, String message) {
        super(messageBytes, message);
    }

    public static SASLChallenge fromMessage(byte[] messageBytes) throws SaslException {
        SASLChallenge saslChallenge = null;
        if (saslChallenge == null) saslChallenge = DIDChallenge.fromMessage(messageBytes);
        if (saslChallenge == null) saslChallenge = VCVPChallenge.fromMessage(messageBytes);
        if (saslChallenge == null) throw new SaslException("Invalid SASL challenge: " + new String(messageBytes, StandardCharsets.UTF_8));
        return saslChallenge;
    }
}
