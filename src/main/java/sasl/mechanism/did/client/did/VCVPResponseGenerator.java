package sasl.mechanism.did.client.did;

import com.danubetech.dataintegrity.signer.LdSigner;
import com.danubetech.dataintegrity.signer.LdSignerRegistry;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.PrivateKeySignerFactory;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import com.danubetech.verifiablecredentials.VerifiableCredentialV2;
import com.danubetech.verifiablecredentials.VerifiablePresentationV2;
import foundation.identity.did.DID;
import foundation.identity.jsonld.JsonLDException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.util.JWSAlgorithmUtil;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.Map;

public class VCVPResponseGenerator {

    private static final Logger log = LogManager.getLogger(VCVPResponseGenerator.class);

    public static String generateResponse(String challenge, DID did, JWK privateKeyJwk, Map<String, VerifiableCredentialV2> verifiableCredentials) throws GeneralSecurityException, JsonLDException, IOException {
        byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);

        VerifiableCredentialV2 verifiableCredential = verifiableCredentials.get("0");

        VerifiablePresentationV2 verifiablePresentation = VerifiablePresentationV2.builder()
                .holder(did.toUri())
                .verifiableCredential(verifiableCredential)
                .build();

        KeyTypeName keyTypeName = KeyTypeName_for_JWK.keyTypeName_for_JWK(privateKeyJwk);
        String algorithm = JWSAlgorithmUtil.getDefaultJWSAlgorithmForKeyTypeName(keyTypeName);
        PrivateKeySigner<?> privateKeySigner = PrivateKeySignerFactory.privateKeySignerForKey(privateKeyJwk, algorithm);

        DataIntegritySuite dataIntegritySuite = DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF;
        LdSigner<?> ldSigner = LdSignerRegistry.getLdSignerByDataIntegritySuite(dataIntegritySuite);
        ldSigner.setCreated(new Date());
        ldSigner.setVerificationMethod(did.toUri().resolve(URI.create("#key-1")));
        ldSigner.setProofPurpose("assertionMethod");
        ldSigner.setSigner(privateKeySigner);

        ldSigner.sign(verifiablePresentation);

        String response = verifiablePresentation.toJson();
        log.debug("Created response for challenge {}: {}", challenge, response);
        return response;
    }
}
