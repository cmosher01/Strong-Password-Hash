package nu.mine.mosher.security.password;

import java.security.*;

final class SaltUtil {
    private SaltUtil() {
        throw new IllegalStateException("Do not instantiate.");
    }

    private static final SecureRandom RANDOM;
    static {
        try {
            RANDOM = SecureRandom.getInstance("NativePRNGNonBlocking");
            for (int i = 0; i < 2027; ++i) {
                RANDOM.nextLong();
            }
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final int SALT_BYTE_COUNT = 16;

    public static byte[] generateRandom() {
        final byte[] salt = new byte[SALT_BYTE_COUNT];
        RANDOM.nextBytes(salt);
        return salt;
    }
}
