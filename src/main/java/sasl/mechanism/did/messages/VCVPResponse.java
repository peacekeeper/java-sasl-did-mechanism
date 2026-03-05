package sasl.mechanism.did.messages;

import com.danubetech.verifiablecredentials.VerifiablePresentationV2;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VCVPResponse extends SASLResponse {

    private static final Pattern PATTERN_VCVP_CHALLENGE = Pattern.compile("(.+)");

    private final VerifiablePresentationV2 verifiablePresentation;

    private VCVPResponse(byte[] messageBytes, String message, VerifiablePresentationV2 verifiablePresentation) {
        super(messageBytes, message);
        this.verifiablePresentation = verifiablePresentation;
    }

    public static VCVPResponse create(VerifiablePresentationV2 verifiablePresentation) {
        String message = verifiablePresentation.toJson();
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        return new VCVPResponse(messageBytes, message, verifiablePresentation);
    }

    public static VCVPResponse fromMessage(byte[] messageBytes) {
        String message = new String(messageBytes, StandardCharsets.UTF_8);
        Matcher matcher = PATTERN_VCVP_CHALLENGE.matcher(message);
        if (! matcher.matches()) return null;
        VerifiablePresentationV2 verifiablePresentation = VerifiablePresentationV2.fromJson(matcher.group(1));
        return new VCVPResponse(messageBytes, message, verifiablePresentation);
    }

    public VerifiablePresentationV2 getVerifiablePresentation() {
        return verifiablePresentation;
    }
}
