package sasl.mechanism.did;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.client.DIDChallengeSaslClientFactory;
import sasl.mechanism.did.server.DIDChallengeSaslServerFactory;

import java.security.Provider;

public final class DIDChallengeSaslProvider extends Provider {

	public static final String MECHANISM_NAME = "DID-CHALLENGE";

	private static final String PROVIDER_NAME = "sasl.mechanism.did";
	private static final String PROVIDER_VERSION = "1.0";
	private static final String PROVIDER_INFO = "A SASL provider for a DID-based authentication mechanism";

	private static final Logger log = LogManager.getLogger(DIDChallengeSaslProvider.class);

	public DIDChallengeSaslProvider() {
		super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
		this.put("SaslClientFactory." + MECHANISM_NAME, DIDChallengeSaslClientFactory.class.getName());
		this.put("SaslServerFactory." + MECHANISM_NAME, DIDChallengeSaslServerFactory.class.getName());
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
