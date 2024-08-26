package demo.sasl.did;

import java.security.Provider;

public class SaslDidMechanismProvider extends Provider {

    public static final String MECHANISM_NAME = "DID-CHALLENGE";

    protected SaslDidMechanismProvider(String name, String versionStr, String info) {
        super(name, versionStr, info);
    }
}