package sasl.mechanism.did.client;

import com.danubetech.keyformats.jose.JWK;
import sasl.mechanism.did.DIDChallengeSaslProvider;
import sasl.mechanism.did.callback.JWKCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

public class DIDChallengeSaslClientFactory implements SaslClientFactory {

    @Override
    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<java.lang.String,?> props, CallbackHandler cbh) throws SaslException {
        if (mechanisms == null || ! Arrays.asList(mechanisms).contains(DIDChallengeSaslProvider.MECHANISM_NAME)) return null;

        Object[] userInfo = this.getUserInfo(authorizationId, cbh);
        String did = (String) userInfo[0];
        JWK privateKey = (JWK) userInfo[1];

        return new DIDChallengeSaslClient(did, privateKey);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> map) {
        return new String[] { DIDChallengeSaslProvider.MECHANISM_NAME };
    }

    private Object[] getUserInfo(String authorizationId, CallbackHandler cbh) throws SaslException {
        if (cbh == null) {
            throw new SaslException("Callback handler to get username/password required");
        } else {
            String namePrompt = "DID: ";
            String textInputCallback = "Private key: ";

            NameCallback nc = authorizationId == null ? new NameCallback(namePrompt) : new NameCallback(namePrompt, authorizationId);
            JWKCallback jwkc = new JWKCallback(textInputCallback, "(JWK)");

            try {
                cbh.handle(new Callback[] { nc, jwkc });
            } catch (IOException | UnsupportedCallbackException ex) {
                throw new SaslException("Failed to handle callback: " + ex.getMessage(), ex);
            }

            String did = nc.getName();
            JWK privateKey;
            try {
                privateKey = JWK.fromJson(jwkc.getText());
            } catch (IOException ex) {
                throw new SaslException("Invalid private key JWK: " + ex.getMessage(), ex);
            }

            return new Object[] { did, privateKey };
        }
    }
}