package demo.sasl.did;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.util.Arrays;
import java.util.Map;

public class SaslDidClientFactory implements SaslClientFactory {

    @Override
    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<java.lang.String,?> props, CallbackHandler cbh) throws SaslException {
        if (mechanisms == null || ! Arrays.asList(mechanisms).contains(SaslDidMechanismProvider.MECHANISM_NAME)) return null;
        return new SaslDidClient(authorizationId);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> map) {
        return new String[] { SaslDidMechanismProvider.MECHANISM_NAME };
    }
}