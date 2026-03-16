package sasl.mechanism.did.server.did;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.messages.DIDChallenge;

import java.util.Random;

public class DIDChallengeGenerator {

    private static final Logger log = LogManager.getLogger(DIDChallengeGenerator.class);

    private static final Random RANDOM = new Random();

    public static DIDChallenge generateChallenge(String realm) {
        String nonce = Long.toString(Math.abs(RANDOM.nextLong()));
        long timestamp = System.currentTimeMillis();
        DIDChallenge didChallenge = DIDChallenge.create(nonce, timestamp, realm);
        log.debug("Generated challenge: {}", didChallenge);
        return didChallenge;
    }
}
