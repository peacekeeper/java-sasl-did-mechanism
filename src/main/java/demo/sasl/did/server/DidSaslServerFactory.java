package demo.sasl.did.server;

import demo.sasl.did.DidSaslProvider;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.util.Map;

public class DidSaslServerFactory implements SaslServerFactory {

    @Override
    public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<java.lang.String,?> props, CallbackHandler cbh) throws SaslException {
        if (mechanism == null || ! mechanism.equals(DidSaslProvider.MECHANISM_NAME)) return null;
        return new DidSaslServer(protocol, serverName, props, cbh);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> map) {
        return new String[] { DidSaslProvider.MECHANISM_NAME };
    }
}