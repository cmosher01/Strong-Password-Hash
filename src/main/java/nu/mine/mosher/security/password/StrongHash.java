package nu.mine.mosher.security.password;

import java.io.Console;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
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
 * and:
 * https://www.owasp.org/index.php/Hashing_Java
 *
 * This class requires that the JVM have access to the PBKDF2WithHmacSHA1 algorithm.
 * Otherwise, it will throw an unchecked exception during class load time.
 *
 * All methods are thread-safe.
 *
 * @author Christopher A. Mosher
 */
public final class StrongHash {
    StrongHash() {
        throw new IllegalStateException("Do not instantiate.");
    }



    private static final int ITERATIONS = 101021;
    private static final int KEY_BYTE_COUNT = 64;
    private static final String HASHING_ALGORITHM_NAME = "PBKDF2WithHmacSHA1";



    static {
        /*
        Make sure our JVM has access to the algorithm we want to use.
         */
        skf();
    }

    private static SecretKeyFactory skf() {
        try {
            return SecretKeyFactory.getInstance(HASHING_ALGORITHM_NAME);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hashFor(final PBEKeySpec spec) throws InvalidKeySpecException {
        return skf().generateSecret(spec).getEncoded();
    }

    private static String serializeHash(final int iterations, final byte[] salt, final byte[] hash) throws InvalidKeySpecException {
        try {
            return new HashedString(iterations, salt, hash).toString();
        } catch (final HashedString.InvalidFormat e) {
            throw new InvalidKeySpecException(e);
        }
    }



    public static void main(final String... args) throws InvalidKeySpecException {
        if (args.length > 0) {
            throw new IllegalArgumentException("Invalid option specified.");
        }

        final Console console = System.console();
        if (Objects.isNull(console)) {
            throw new UnsupportedOperationException("Pass-phrases must be entered manually in the console.");
        }

        final char[] password = console.readPassword("%s: ", "pass-phrase");

        System.out.println(hash(new String(password)));
        System.out.flush();
    }



    /**
     * Checks if the given (guessed) password is valid according to the
     * given hash. The given hash is assumed to be a hash of the correct
     * password as returned by a previous call to {@link #hash(String)}.
     *
     * @param guess password to validate, cannot be null (can be empty, but empty will always return false)
     * @param storedHashRepresentation hash of the correct password, cannot be null or empty or in an invalid format
     * @return true if the guess is valid. An empty guess is never valid.
     * @throws HashedString.InvalidFormat if the storedHashRepresentation is in an invalid format, or is empty
     * @throws NullPointerException if either argument is null
     */
    public static boolean isPasswordValid(final String guess, final String storedHashRepresentation) throws HashedString.InvalidFormat {
        if (Objects.requireNonNull(guess).isEmpty()) {
            return false;
        }
        final HashedString stored = HashedString.create(Objects.requireNonNull(storedHashRepresentation));
        final PBEKeySpec spec = new PBEKeySpec(guess.toCharArray(), stored.salt(), stored.iterations(), stored.hashBitCount());
        try {
            return Arrays.equals(hashFor(spec), stored.hash());
        } catch (final InvalidKeySpecException ignore) {
            return false;
        }
    }

    /**
     * Creates a secure hash for the given password, in an unspecified internal format.
     * The format is forwardly compatible with future versions of this library.
     * The returned string is suitable to be stored in a database and retrieved
     * at a later time for verifying candidate passwords.
     *
     * @param password The string (password, pass-phrase, etc.) to compute the hash of.
     *                 Cannot be null or empty.
     * @return The secure hash (internal format).
     * @throws InvalidKeySpecException if the given password cannot be hashed, or is empty. In this case,
     * the caller should refuse to use the password.
     * @throws NullPointerException if the password argument is null
     */
    public static String hash(final String password) throws InvalidKeySpecException {
        if (Objects.requireNonNull(password).isEmpty()) {
            throw new InvalidKeySpecException("Password cannot be empty.");
        }
        final byte[] salt = SaltUtil.generateRandom();
        final PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_BYTE_COUNT * Byte.SIZE);
        return serializeHash(ITERATIONS, salt, hashFor(spec));
    }
}
