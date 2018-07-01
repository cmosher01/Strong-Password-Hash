package nu.mine.mosher;

import com.google.common.io.BaseEncoding;
import java.io.Console;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Strong hashing library and command-line program.
 *
 * Based on code from:
 * https://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
 * "Generate Secure Password Hash : MD5, SHA, PBKDF2, BCrypt Examples"
 * July 22, 2013 by Lokesh Gupta
 *
 * @author Christopher A. Mosher
 */
public class StrongHash {
    private static final int ITERATIONS = 101021;
    private static final int KEY_LENGTH = 64 * 8;
    private static final int SALT_BYTE_COUNT = 16;
    private static final int SYSTEM_SEED_BYTE_COUNT = 29;



    public static void main(final String... args) {
        final Console console = System.console();
        if (Objects.isNull(console)) {
            throw new UnsupportedOperationException("Pass-phrases must be entered manually in the console.");
        }

        final char[] password = console.readPassword("%s: ", "pass-phrase");
        if (Objects.isNull(password) || password.length == 0) {
            return;
        }

        System.out.println(hash(new String(password)));
        System.out.flush();
    }



    public static boolean isPasswordValid(final String guess, final String storedHash) {
        try {
            final String[] parts = storedHash.split(":");
            final int iterations = Integer.parseInt(parts[0]);
            final byte[] salt = unhex(parts[1]);
            final byte[] hash = unhex(parts[2]);

            final PBEKeySpec spec = new PBEKeySpec(guess.toCharArray(), salt, iterations, hash.length * 8);
            final SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            final byte[] testHash = skf.generateSecret(spec).getEncoded();

            return Arrays.equals(testHash, hash);
        } catch (final Throwable e) {
            throw new IllegalStateException(e);
        }
    }

    public static String hash(final String password) {
        try {
            final byte[] salt = generateRandomSalt();

            final PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            final SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            final byte[] hash = skf.generateSecret(spec).getEncoded();

            return ITERATIONS + ":" + hex(salt) + ":" + hex(hash);
        } catch (final Throwable e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(final byte[] rb) {
        return BaseEncoding.base16().encode(rb);
    }

    private static byte[] unhex(final String s) {
        return BaseEncoding.base16().decode(s);
    }



    private static final SecureRandom RANDOM;

    static {
        synchronized (StrongHash.class) {
            try {
                RANDOM = SecureRandom.getInstance("SHA1PRNG");
                RANDOM.setSeed(RANDOM.generateSeed(SYSTEM_SEED_BYTE_COUNT));

                // just make sure our JVM has access to PBKDF algorithm:
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            } catch (final NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static byte[] generateRandomSalt() {
        final byte[] salt = new byte[SALT_BYTE_COUNT];

        synchronized (StrongHash.class) {
            RANDOM.nextBytes(salt);
        }

        return salt;
    }
}
