package sasl.mechanism.did.server.did;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.verifier.LdVerifier;
import com.danubetech.dataintegrity.verifier.LdVerifierRegistry;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifierFactory;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import com.danubetech.verifiablecredentials.VerifiablePresentationV2;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.messages.VCVPChallenge;
import sasl.mechanism.did.messages.VCVPResponse;
import sasl.mechanism.did.util.JWSAlgorithmUtil;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveResult;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

public class VCVPResponseVerifier {

    private static final Logger log = LogManager.getLogger(VCVPResponseVerifier.class);

    private static final ClientUniResolver clientUniResolver = ClientUniResolver.create(URI.create("https://dev.uniresolver.io/1.0/"));

    public static void verifyResponse(VCVPChallenge vcvpChallenge, VCVPResponse vcvpResponse) throws ResolutionException, GeneralSecurityException, IOException, JsonLDException {

        JWK publicKeyJwk = dereferenceJWK(vcvpResponse.getVerifiablePresentation());

        KeyTypeName keyTypeName = KeyTypeName_for_JWK.keyTypeName_for_JWK(publicKeyJwk);
        String algorithm = JWSAlgorithmUtil.getDefaultJWSAlgorithmForKeyTypeName(keyTypeName);
        PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(publicKeyJwk, algorithm);

        DataIntegrityProof dataIntegrityProof = vcvpResponse.getVerifiablePresentation().getDataIntegrityProof();
        if (dataIntegrityProof == null) throw new GeneralSecurityException("No data integrity proof found in VP");

        DataIntegritySuite dataIntegritySuite = DataIntegritySuites.findDataIntegritySuiteByTerm(dataIntegrityProof.getType());
        LdVerifier<?> ldVerifier = LdVerifierRegistry.getLdVerifierByDataIntegritySuite(dataIntegritySuite);
        ldVerifier.setVerifier(publicKeyVerifier);
        boolean verified = ldVerifier.verify(vcvpResponse.getVerifiablePresentation());
        log.debug("Verified proof {} for VP {}: {}", dataIntegrityProof, vcvpResponse.getVerifiablePresentationString(), verified);
        if (! verified) throw new GeneralSecurityException("VC/VP response verification failed.");
    }

    private static JWK dereferenceJWK(VerifiablePresentationV2 verifiablePresentationV2) throws ResolutionException, IOException {

        String holder = verifiablePresentationV2.getHolder().toString();

        ResolveResult resolveResult = clientUniResolver.resolve(holder);
        DIDDocument didDocument = resolveResult.getDidDocument();

        List<VerificationMethod> authenticationVerificationMethods = didDocument.getAuthenticationVerificationMethodsDereferenced();
        if (authenticationVerificationMethods == null || authenticationVerificationMethods.isEmpty()) throw new IllegalArgumentException("No authentication verification method for holder " + holder);

        VerificationMethod verificationMethod = authenticationVerificationMethods.get(0);
        Map<String, Object> publicKeyJwk = verificationMethod.getPublicKeyJwk();
        if (publicKeyJwk == null || publicKeyJwk.isEmpty()) throw new IllegalArgumentException("No public key for holder " + holder);

        return JWK.fromMap(publicKeyJwk);
    }
}
