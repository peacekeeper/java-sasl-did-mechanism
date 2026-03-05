package sasl.mechanism.did.callback;

import java.io.Serial;

public class VCSCallback extends javax.security.auth.callback.TextInputCallback {
    @Serial
    private static final long serialVersionUID = 7601923847561029384L;

    public VCSCallback(String prompt) {
        super(prompt);
    }

    public VCSCallback(String prompt, String defaultText) {
        super(prompt, defaultText);
    }
}
