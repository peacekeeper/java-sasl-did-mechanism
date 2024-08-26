package demo.sasl.did;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.util.Map;

public class SaslDidServerFactory implements SaslServerFactory {

    @Override
    public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<java.lang.String,?> props, CallbackHandler cbh) throws SaslException {
        if (mechanism == null || ! mechanism.equals(SaslDidMechanismProvider.MECHANISM_NAME)) return null;
        return new SaslDidServer();
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> map) {
        return new String[] { SaslDidMechanismProvider.MECHANISM_NAME };
    }
}