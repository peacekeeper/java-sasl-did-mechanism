package demo.sasl.did.server;

import java.util.Random;

public class ChallengeGenerator {

    private static final Random RANDOM = new Random();

    public static String generateChallenge(String serverName) {
        long rand = RANDOM.nextLong();
        long timestamp = System.currentTimeMillis();
        return "<" + rand + '.' + timestamp + '@' + serverName + '>';
    }
}
