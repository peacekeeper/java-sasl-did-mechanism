package demo.sasl.did.server;

import com.google.crypto.tink.subtle.Ed25519Verify;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import io.leonard.Base58;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveResult;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

public class SignatureVerifier {

    public static void verifySignature(String challenge, String did, String signature) throws ResolutionException, GeneralSecurityException {
        ClientUniResolver clientUniResolver = new ClientUniResolver();

        ResolveResult resolveResult = clientUniResolver.resolve(did);
        DIDDocument didDocument = resolveResult.toResolveDataModelResult().getDidDocument();

        List<VerificationMethod> authenticationVerificationMethods = didDocument.getAuthenticationVerificationMethodsDereferenced();
        if (authenticationVerificationMethods == null || authenticationVerificationMethods.isEmpty()) throw new IllegalArgumentException("No authentication verification method for DID " + did);

        VerificationMethod verificationMethod = authenticationVerificationMethods.getFirst();
        String publicKey = verificationMethod.getPublicKeyBase58();
        byte[] publicKeyBytes = Base58.decode(publicKey);

        byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = Base58.decode(signature);
        new Ed25519Verify(publicKeyBytes).verify(signatureBytes, challengeBytes);
    }
}
