package sasl.did.mechanism;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.did.mechanism.client.DidSaslClientFactory;
import sasl.did.mechanism.server.DidSaslServerFactory;

import java.security.Provider;

public final class DidSaslProvider extends Provider {

	public static final String MECHANISM_NAME = "DID-CHALLENGE";

	private static final String PROVIDER_NAME = "demo.sasl.did";
	private static final String PROVIDER_VERSION = "1.0";
	private static final String PROVIDER_INFO = "A SASL provider for a DID-based authentication mechanism";

	private static final Logger log = LogManager.getLogger(DidSaslProvider.class);

	public DidSaslProvider() {
		super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
		this.put("SaslClientFactory." + MECHANISM_NAME, DidSaslClientFactory.class.getName());
		this.put("SaslServerFactory." + MECHANISM_NAME, DidSaslServerFactory.class.getName());
	}

	@Override
	protected synchronized void putService(Service s) {
		log.info("Putting SASL service '{}' with class '{}'", s.getAlgorithm(), s.getClassName());
		super.putService(s);
	}

	@Override
	protected synchronized void removeService(Service s) {
		log.info("Removing SASL service '{}' with class '{}'", s.getAlgorithm(), s.getClassName());
		super.removeService(s);
	}
}
