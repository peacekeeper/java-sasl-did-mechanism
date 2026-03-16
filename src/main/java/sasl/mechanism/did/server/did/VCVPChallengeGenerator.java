package sasl.mechanism.did.server.did;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sasl.mechanism.did.messages.VCVPChallenge;

import java.util.Random;

public class VCVPChallengeGenerator {

    private static final Logger log = LogManager.getLogger(VCVPChallengeGenerator.class);

    private static final Random RANDOM = new Random();

    public static VCVPChallenge generateChallenge(String vcType, String realm) {
        String nonce = Long.toString(Math.abs(RANDOM.nextLong()));
        long timestamp = System.currentTimeMillis();
        VCVPChallenge vcvpChallenge = VCVPChallenge.create(nonce, timestamp, vcType, realm);
        log.debug("Generated challenge: {}", vcvpChallenge);
        return vcvpChallenge;
    }
}
