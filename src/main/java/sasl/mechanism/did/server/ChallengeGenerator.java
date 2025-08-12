package sasl.mechanism.did.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Random;

public class ChallengeGenerator {

    private static final Logger log = LogManager.getLogger(ChallengeGenerator.class);

    private static final Random RANDOM = new Random();

    public static String generateChallenge(String serverName) {
        long rand = RANDOM.nextLong();
        long timestamp = System.currentTimeMillis();
        String challenge = "<" + rand + '.' + timestamp + '@' + serverName + '>';
        log.debug("Generated challenge: {}", challenge);
        return challenge;
    }
}
