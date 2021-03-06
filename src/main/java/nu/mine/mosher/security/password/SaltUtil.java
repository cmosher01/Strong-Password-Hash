package nu.mine.mosher.security.password;

import java.security.SecureRandom;

final class SaltUtil {
    private SaltUtil() {
        throw new IllegalStateException("Do not instantiate.");
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int SALT_BYTE_COUNT = 16;

    public static byte[] generateRandom() {
        final byte[] salt = new byte[SALT_BYTE_COUNT];
        RANDOM.nextBytes(salt);
        return salt;
    }
}
