package nu.mine.mosher.security.password;

import com.google.common.io.BaseEncoding;

import java.util.Objects;

public final class HashedString {
    private static final int MIN_ITERATIONS = 1;
    private static final int MAX_ITERATIONS = 1 << 28;
    private static final String DELIMITER = ":";

    private final int iterations;
    private final byte[] salt;
    private final byte[] hash;

    public HashedString(final int iterations, final byte[] salt, final byte[] hash) throws InvalidFormat {
        try {
            this.iterations = validIterationRange(iterations);
            this.salt = nonEmptyCopy(salt);
            this.hash = nonEmptyCopy(hash);
        } catch (final InvalidFormat e) {
            throw e;
        } catch (final Throwable cause) {
            throw new InvalidFormat(cause);
        }
    }

    private static int validIterationRange(final int iterations) throws InvalidFormat {
        if (iterations < MIN_ITERATIONS || MAX_ITERATIONS < iterations) {
            throw new InvalidFormat("Hash algorithm iterations must be between "+MIN_ITERATIONS+" and "+MAX_ITERATIONS);
        }
        return iterations;
    }

    private static byte[] nonEmptyCopy(final byte[] untrusted) throws InvalidFormat {
        final byte[] klone = Objects.requireNonNull(untrusted).clone();
        if (klone.length == 0) {
            throw new InvalidFormat("Missing salt or hash.");
        }
        return klone;
    }

    public static HashedString create(final String untrustedInternalRepresentation) throws InvalidFormat {
        try {
            final String[] parts = Objects.requireNonNull(untrustedInternalRepresentation).split(DELIMITER, 3);

            final int iterations = Integer.parseInt(parts[0]);
            final byte[] salt = unhex(parts[1]);
            final byte[] hash = unhex(parts[2]);

            return new HashedString(iterations, salt, hash);
        } catch (final InvalidFormat e) {
            throw e;
        } catch (final Throwable cause) {
            throw new InvalidFormat(cause);
        }
    }

    @Override
    public String toString() {
        return Integer.toString(this.iterations) + DELIMITER + hex(this.salt) + DELIMITER + hex(this.hash);
    }

    private static String hex(final byte[] rb) {
        return BaseEncoding.base16().encode(rb);
    }

    private static byte[] unhex(final String s) {
        return BaseEncoding.base16().decode(s);
    }

    public byte[] salt() {
        return this.salt.clone();
    }

    public int iterations() {
        return this.iterations;
    }

    public int hashBitCount() {
        return this.hash.length * Byte.SIZE;
    }

    public byte[] hash() {
        return this.hash.clone();
    }



    public static class InvalidFormat extends Exception {
        private InvalidFormat(final String msg) {
            super(msg);
        }
        private InvalidFormat(final Throwable cause) {
            super("Invalid hashed format", cause);
        }
    }
}
