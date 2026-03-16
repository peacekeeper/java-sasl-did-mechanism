package sasl.mechanism.did.messages;

import foundation.identity.did.DID;
import foundation.identity.did.parser.ParserException;
import org.apache.commons.codec.binary.Base64;

import javax.security.sasl.SaslException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DIDResponse extends SASLResponse {

    private static final Pattern PATTERN_DID_RESPONSE = Pattern.compile("([^ ]+) ([^ ]+)");

    private final String didString;
    private final String signatureString;

    private final DID did;
    private final byte[] signature;

    private DIDResponse(byte[] messageBytes, String message, String didString, String signatureString, DID did, byte[] signature) {
        super(messageBytes, message);
        this.didString = didString;
        this.signatureString = signatureString;
        this.did = did;
        this.signature = signature;
    }

    public static DIDResponse create(DID did, byte[] signature) {
        String didString = did.toString();
        String signatureString = Base64.encodeBase64URLSafeString(signature);
        String message = didString + " " + signatureString;
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        return new DIDResponse(messageBytes, message, didString, signatureString, did, signature);
    }

    public static DIDResponse fromMessage(byte[] messageBytes) throws SaslException {
        String message = new String(messageBytes, StandardCharsets.UTF_8);
        Matcher matcher = PATTERN_DID_RESPONSE.matcher(message);
        if (! matcher.matches()) return null;
        String didString = matcher.group(1);
        String signatureString = matcher.group(2);
        DID did;
        try {
            did = DID.fromString(didString);
        } catch (ParserException ex) {
            throw new SaslException("Invalid DID '" + didString + "' in SASL response: " + ex.getMessage(), ex);
        }
        byte[] signature = Base64.decodeBase64(signatureString);
        return new DIDResponse(messageBytes, message, didString, signatureString, did, signature);
    }

    public String getDidString() {
        return didString;
    }

    public String getSignatureString() {
        return signatureString;
    }

    public DID getDid() {
        return did;
    }

    public byte[] getSignature() {
        return signature;
    }
}
