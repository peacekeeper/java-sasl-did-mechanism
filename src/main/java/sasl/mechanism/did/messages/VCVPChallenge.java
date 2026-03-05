package sasl.mechanism.did.messages;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VCVPChallenge extends SASLChallenge {

    private static final Pattern PATTERN_VCVP_CHALLENGE = Pattern.compile("<([^.]+)\\.([^.]+)\\.([^.]+)@([^.]+)>");

    private final String nonce;
    private final long timestamp;
    private final String vcType;
    private final String realm;

    private VCVPChallenge(byte[] messageBytes, String message, String nonce, long timestamp, String vcType, String realm) {
        super(messageBytes, message);
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.vcType = vcType;
        this.realm = realm;
    }

    public static VCVPChallenge create(String nonce, long timestamp, String vcType, String realm) {
        String message = "<" + nonce + "." + timestamp + "@" + realm + ">";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        return new VCVPChallenge(messageBytes, message, nonce, timestamp, vcType, realm);
    }

    public static VCVPChallenge fromMessage(byte[] messageBytes) {
        String message = new String(messageBytes, StandardCharsets.UTF_8);
        Matcher matcher = PATTERN_VCVP_CHALLENGE.matcher(message);
        if (! matcher.matches()) return null;
        String none = matcher.group(1);
        long timestamp = Long.parseLong(matcher.group(2));
        String vcType = matcher.group(3);
        String realm = matcher.group(4);
        return new VCVPChallenge(messageBytes, message, none, timestamp, vcType, realm);
    }

    public String getNonce() {
        return nonce;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getVcType() {
        return vcType;
    }

    public String getRealm() {
        return realm;
    }
}
