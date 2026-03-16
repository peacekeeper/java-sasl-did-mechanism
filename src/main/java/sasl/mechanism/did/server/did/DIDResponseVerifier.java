package sasl.mechanism.did.server.did;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifierFactory;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.messages.DIDChallenge;
import sasl.mechanism.did.messages.DIDResponse;
import sasl.mechanism.did.util.JWSAlgorithmUtil;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveResult;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

public class DIDResponseVerifier {

    private static final Logger log = LogManager.getLogger(DIDResponseVerifier.class);

    private static final ClientUniResolver clientUniResolver = ClientUniResolver.create(URI.create("https://dev.uniresolver.io/1.0/"));

    public static void verifyResponse(DIDChallenge didChallenge, DIDResponse didResponse) throws ResolutionException, GeneralSecurityException, IOException {

        JWK publicKeyJwk = dereferenceJWK(didResponse.getDid());

        KeyTypeName keyTypeName = KeyTypeName_for_JWK.keyTypeName_for_JWK(publicKeyJwk);
        String algorithm = JWSAlgorithmUtil.getDefaultJWSAlgorithmForKeyTypeName(keyTypeName);
        PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(publicKeyJwk, algorithm);

        byte[] challengeBytes = didChallenge.getMessageBytes();
        byte[] signatureBytes = didResponse.getSignature();
        boolean verified = publicKeyVerifier.verify(challengeBytes, signatureBytes, algorithm);
        log.debug("Verified signature {} for challenge {}: {}", didResponse.getSignatureString(), didChallenge.getMessage(), verified);
        if (! verified) throw new GeneralSecurityException("DID response verification failed.");
    }

    private static JWK dereferenceJWK(DID did) throws ResolutionException, IOException {

        ResolveResult resolveResult = clientUniResolver.resolve(did.getDidString());
        DIDDocument didDocument = resolveResult.getDidDocument();

        List<VerificationMethod> authenticationVerificationMethods = didDocument.getAuthenticationVerificationMethodsDereferenced();
        if (authenticationVerificationMethods == null || authenticationVerificationMethods.isEmpty()) throw new IllegalArgumentException("No authentication verification method for DID " + did);

        VerificationMethod verificationMethod = authenticationVerificationMethods.get(0);
        Map<String, Object> publicKeyJwk = verificationMethod.getPublicKeyJwk();
        if (publicKeyJwk == null || publicKeyJwk.isEmpty()) throw new IllegalArgumentException("No public key for DID " + did);

        return JWK.fromMap(publicKeyJwk);
    }
}
