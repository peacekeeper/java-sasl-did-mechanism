package sasl.mechanism.did.callback;

public class JWKCallback extends javax.security.auth.callback.TextInputCallback {
    private static final long serialVersionUID = -1378003535968721493L;

    public JWKCallback(java.lang.String prompt) {
        super(prompt);
    }

    public JWKCallback(java.lang.String prompt, java.lang.String defaultText) {
        super(prompt, defaultText);
    }
}
