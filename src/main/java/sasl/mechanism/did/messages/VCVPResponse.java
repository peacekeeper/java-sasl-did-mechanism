package sasl.mechanism.did.messages;

import com.danubetech.verifiablecredentials.VerifiablePresentationV2;

import javax.security.sasl.SaslException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VCVPResponse extends SASLResponse {

    private static final Pattern PATTERN_VCVP_CHALLENGE = Pattern.compile("(.+)");

    private final String verifiablePresentationString;

    private final VerifiablePresentationV2 verifiablePresentation;

    private VCVPResponse(byte[] messageBytes, String message, String verifiablePresentationString, VerifiablePresentationV2 verifiablePresentation) {
        super(messageBytes, message);
        this.verifiablePresentationString = verifiablePresentationString;
        this.verifiablePresentation = verifiablePresentation;
    }

    public static VCVPResponse create(VerifiablePresentationV2 verifiablePresentation) {
        String verifiablePresentationString = verifiablePresentation.toJson();
        String message = verifiablePresentationString;
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        return new VCVPResponse(messageBytes, message, verifiablePresentationString, verifiablePresentation);
    }

    public static VCVPResponse fromMessage(byte[] messageBytes) throws SaslException {
        String message = new String(messageBytes, StandardCharsets.UTF_8);
        Matcher matcher = PATTERN_VCVP_CHALLENGE.matcher(message);
        if (! matcher.matches()) return null;
        String verifiablePresentationString = matcher.group(1);
        VerifiablePresentationV2 verifiablePresentation = VerifiablePresentationV2.fromJson(verifiablePresentationString);
        return new VCVPResponse(messageBytes, message, verifiablePresentationString, verifiablePresentation);
    }

    public String getVerifiablePresentationString() {
        return verifiablePresentationString;
    }

    public VerifiablePresentationV2 getVerifiablePresentation() {
        return verifiablePresentation;
    }
}
