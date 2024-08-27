package sasl.did.mechanism.server;

import com.google.crypto.tink.subtle.Ed25519Verify;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import io.leonard.Base58;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveResult;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

public class SignatureVerifier {

    public static void verifySignature(String challenge, String did, String signature) throws ResolutionException, GeneralSecurityException, ParseException {
        ClientUniResolver clientUniResolver = ClientUniResolver.create(URI.create("https://dev.uniresolver.io/1.0/"));

        ResolveResult resolveResult = clientUniResolver.resolve(did);
        DIDDocument didDocument = resolveResult.toResolveDataModelResult().getDidDocument();

        List<VerificationMethod> authenticationVerificationMethods = didDocument.getAuthenticationVerificationMethodsDereferenced();
        if (authenticationVerificationMethods == null || authenticationVerificationMethods.isEmpty()) throw new IllegalArgumentException("No authentication verification method for DID " + did);

        VerificationMethod verificationMethod = authenticationVerificationMethods.get(0);
        Map<String, Object> publicKey = verificationMethod.getPublicKeyJwk();
        if (publicKey == null || publicKey.isEmpty()) throw new IllegalArgumentException("No public key for DID " + did);

        OctetKeyPair jwk = (OctetKeyPair) JWK.parse(publicKey);
        byte[] publicKeyBytes = jwk.getDecodedX();

        byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = Base58.decode(signature);
        new Ed25519Verify(publicKeyBytes).verify(signatureBytes, challengeBytes);
    }
}
