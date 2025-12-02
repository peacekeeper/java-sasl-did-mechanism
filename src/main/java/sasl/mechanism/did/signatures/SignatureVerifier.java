package sasl.mechanism.did.signatures;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifierFactory;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import io.leonard.Base58;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveResult;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

public class SignatureVerifier {

    private static final Logger log = LogManager.getLogger(SignatureVerifier.class);

    private static final ClientUniResolver clientUniResolver = ClientUniResolver.create(URI.create("https://dev.uniresolver.io/1.0/"));

    public static void verifySignature(String challenge, String did, String signature) throws ResolutionException, GeneralSecurityException, IOException {

        JWK publicKeyJwk = dereferenceJWK(did);

        KeyTypeName keyTypeName = KeyTypeName_for_JWK.keyTypeName_for_JWK(publicKeyJwk);
        String algorithm = JWSAlgorithms.JWS_ALGORITHMS.get(keyTypeName);
        PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(publicKeyJwk, algorithm);

        byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = Base58.decode(signature);
        boolean verified = publicKeyVerifier.verify(challengeBytes, signatureBytes, algorithm);
        log.debug("Verified signature {} for challenge {}: {}", signature, challenge, verified);
        if (! verified) throw new GeneralSecurityException("Signature verification failed.");
    }

    private static JWK dereferenceJWK(String did) throws ResolutionException, IOException {

        ResolveResult resolveResult = clientUniResolver.resolve(did);
        DIDDocument didDocument = resolveResult.getDidDocument();

        List<VerificationMethod> authenticationVerificationMethods = didDocument.getAuthenticationVerificationMethodsDereferenced();
        if (authenticationVerificationMethods == null || authenticationVerificationMethods.isEmpty()) throw new IllegalArgumentException("No authentication verification method for DID " + did);

        VerificationMethod verificationMethod = authenticationVerificationMethods.get(0);
        Map<String, Object> publicKeyJwk = verificationMethod.getPublicKeyJwk();
        if (publicKeyJwk == null || publicKeyJwk.isEmpty()) throw new IllegalArgumentException("No public key for DID " + did);

        return JWK.fromMap(publicKeyJwk);
    }
}
