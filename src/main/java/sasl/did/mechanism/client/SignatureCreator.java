package sasl.did.mechanism.client;

import com.google.crypto.tink.subtle.Ed25519Sign;
import io.leonard.Base58;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class SignatureCreator {

    public static String createSignature(String challenge, byte[] privateKeyBytes) throws GeneralSecurityException {
        byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);

        byte[] signatureValue = new Ed25519Sign(privateKeyBytes).sign(challengeBytes);
        return Base58.encode(signatureValue);
    }
}
