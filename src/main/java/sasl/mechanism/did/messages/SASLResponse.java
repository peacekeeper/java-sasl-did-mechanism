package sasl.mechanism.did.messages;

import foundation.identity.did.parser.ParserException;

import javax.security.sasl.SaslException;
import java.nio.charset.StandardCharsets;

public class SASLResponse extends SASLMessage {

    protected SASLResponse(byte[] messageBytes, String message) {
        super(messageBytes, message);
    }

    public static SASLResponse fromMessage(byte[] messageBytes) throws SaslException, ParserException {
        SASLResponse saslResponse = null;
        if (saslResponse == null) saslResponse = DIDResponse.fromMessage(messageBytes);
        if (saslResponse == null) saslResponse = VCVPResponse.fromMessage(messageBytes);
        if (saslResponse == null) throw new SaslException("Invalid SASL response: " + new String(messageBytes, StandardCharsets.UTF_8));
        return saslResponse;
    }
}
