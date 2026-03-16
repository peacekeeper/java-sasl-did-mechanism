package sasl.mechanism.did.messages;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DIDChallenge extends SASLChallenge {

    private static final Pattern PATTERN_DID_CHALLENGE = Pattern.compile("<([^.]+)\\.([^.]+)@([^.]+)>");

    private final String nonce;
    private final long timestamp;
    private final String realm;

    private DIDChallenge(byte[] messageBytes, String message, String nonce, long timestamp, String realm) {
        super(messageBytes, message);
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.realm = realm;
    }

    public static DIDChallenge create(String nonce, long timestamp, String realm) {
        String message = "<" + nonce + "." + timestamp + "@" + realm + ">";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        return new DIDChallenge(messageBytes, message, nonce, timestamp, realm);
    }

    public static DIDChallenge fromMessage(byte[] messageBytes) {
        String message = new String(messageBytes, StandardCharsets.UTF_8);
        Matcher matcher = PATTERN_DID_CHALLENGE.matcher(message);
        if (! matcher.matches()) return null;
        String nonce = matcher.group(1);
        long timestamp = Long.parseLong(matcher.group(2));
        String realm = matcher.group(3);
        return new DIDChallenge(messageBytes, message, nonce, timestamp, realm);
    }

    public String getNonce() {
        return nonce;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getRealm() {
        return realm;
    }
}
