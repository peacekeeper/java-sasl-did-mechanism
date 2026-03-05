package sasl.mechanism.did.messages;

import foundation.identity.did.DID;
import foundation.identity.did.parser.ParserException;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DIDResponse extends SASLResponse {

    private static final Pattern PATTERN_DID_RESPONSE = Pattern.compile("([^ ]+) ([^ ]+)");

    private final DID did;
    private final byte[] signature;

    private DIDResponse(byte[] messageBytes, String message, DID did, byte[] signature) {
        super(messageBytes, message);
        this.did = did;
        this.signature = signature;
    }

    public static DIDResponse create(DID did, byte[] signature) {
        String message = did.toString() + " " + Base64.toBase64String(signature);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        return new DIDResponse(messageBytes, message, did, signature);
    }

    public static DIDResponse fromMessage(byte[] messageBytes) throws ParserException {
        String message = new String(messageBytes, StandardCharsets.UTF_8);
        Matcher matcher = PATTERN_DID_RESPONSE.matcher(message);
        if (! matcher.matches()) return null;
        DID did = DID.fromString(matcher.group(1));
        byte[] signature = Base64.decode(matcher.group(2));
        return new DIDResponse(messageBytes, message, did, signature);
    }

    public DID getDid() {
        return did;
    }

    public byte[] getSignature() {
        return signature;
    }
}
