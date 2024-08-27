package sasl.did.mechanism.client;

import sasl.did.mechanism.DidSaslProvider;
import io.leonard.Base58;

import javax.security.auth.callback.*;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

public class DidSaslClientFactory implements SaslClientFactory {

    @Override
    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<java.lang.String,?> props, CallbackHandler cbh) throws SaslException {
        if (mechanisms == null || ! Arrays.asList(mechanisms).contains(DidSaslProvider.MECHANISM_NAME)) return null;

        Object[] userInfo = this.getUserInfo(authorizationId, cbh);
        String did = (String) userInfo[0];
        byte[] privateKeyBytes = (byte[]) userInfo[1];

        return new DidSaslClient(did, privateKeyBytes);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> map) {
        return new String[] { DidSaslProvider.MECHANISM_NAME };
    }

    private Object[] getUserInfo(String authorizationId, CallbackHandler cbh) throws SaslException {
        if (cbh == null) {
            throw new SaslException("Callback handler to get username/password required");
        } else {
            String namePrompt = "DID: ";
            String textInputCallback = "Private key: ";

            NameCallback ncb = authorizationId == null ? new NameCallback(namePrompt) : new NameCallback(namePrompt, authorizationId);
            TextInputCallback ticb = new TextInputCallback(textInputCallback, "(base58 encoded)");

            try {
                cbh.handle(new Callback[] { ncb, ticb });
            } catch (IOException | UnsupportedCallbackException ex) {
                throw new SaslException("Failed to handle callback: " + ex.getMessage(), ex);
            }

            String did = ncb.getName();
            String privateKey = ticb.getText();
            byte[] privateKeyBytes = Base58.decode(privateKey);

            return new Object[] { did, privateKeyBytes };
        }
    }
}