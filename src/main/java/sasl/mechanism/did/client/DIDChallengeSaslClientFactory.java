package sasl.mechanism.did.client;

import com.danubetech.keyformats.jose.JWK;
import com.danubetech.verifiablecredentials.VerifiableCredentialV2;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.did.DID;
import foundation.identity.did.parser.ParserException;
import sasl.mechanism.did.DIDChallengeSaslProvider;
import sasl.mechanism.did.callback.JWKCallback;
import sasl.mechanism.did.callback.VCSCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public class DIDChallengeSaslClientFactory implements SaslClientFactory {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<java.lang.String,?> props, CallbackHandler cbh) throws SaslException {
        if (mechanisms == null || ! Arrays.asList(mechanisms).contains(DIDChallengeSaslProvider.MECHANISM_NAME)) return null;

        Object[] userInfo = this.getUserInfo(authorizationId, cbh);
        DID did = (DID) userInfo[0];
        JWK privateKey = (JWK) userInfo[1];
        Map<String, VerifiableCredentialV2> verifiableCredentials = (Map<String, VerifiableCredentialV2>) userInfo[2];

        return new DIDChallengeSaslClient(did, privateKey, verifiableCredentials);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> map) {
        return new String[] { DIDChallengeSaslProvider.MECHANISM_NAME };
    }

    private Object[] getUserInfo(String authorizationId, CallbackHandler cbh) throws SaslException {
        if (cbh == null) {
            throw new SaslException("Callback handler to get username/password required");
        } else {
            String namePrompt = "Client DID: ";
            String jwkPrompt = "Client Private Key: ";
            String vcvpPrompt = "Client Verifiable Credentials: ";

            NameCallback nc = authorizationId == null ? new NameCallback(namePrompt) : new NameCallback(namePrompt, authorizationId);
            JWKCallback jwkc = new JWKCallback(jwkPrompt, "(JWK)");
            VCSCallback vcsc = new VCSCallback(vcvpPrompt, "(VCS)");

            try {
                cbh.handle(new Callback[] { nc, jwkc, vcsc });
            } catch (IOException | UnsupportedCallbackException ex) {
                throw new SaslException("Failed to handle callback: " + ex.getMessage(), ex);
            }

            DID did;
            try {
                did = DID.fromString(URLDecoder.decode(nc.getName(), StandardCharsets.UTF_8));
            } catch (ParserException ex) {
                throw new SaslException("Invalid DID: " + ex.getMessage(), ex);
            }
            JWK privateKey;
            try {
                privateKey = JWK.fromJson(jwkc.getText());
            } catch (IOException ex) {
                throw new SaslException("Invalid Private Key JWK: " + ex.getMessage(), ex);
            }
            Map<String, VerifiableCredentialV2> verifiableCredentials;
            try {
                verifiableCredentials = ((Map<String, Map<String, Object>>) objectMapper.readValue(vcsc.getText(), Map.class)).entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> VerifiableCredentialV2.fromMap(e.getValue())));
            } catch (JsonProcessingException ex) {
                throw new SaslException("Invalid Verifiable Credentials: " + ex.getMessage(), ex);
            }

            return new Object[] { did, privateKey, verifiableCredentials };
        }
    }
}