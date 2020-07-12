package nu.mine.mosher.security.password;

//import com.google.common.io.BaseEncoding;

import java.util.*;

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
        return this.iterations + DELIMITER + hex(this.salt) + DELIMITER + hex(this.hash);
    }

    static String hex(final byte[] rb) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : rb) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    static byte[] unhex(final String s) {
        if (s.length() % 2 == 1) {
            throw new IllegalArgumentException("Invalid hex String, must be even number of characters.");
        }

        final byte[] bytes = new byte[s.length() / 2];
        for (int i = 0; i < s.length(); i += 2) {
            bytes[i / 2] = hexToByte(s.substring(i, i + 2));
        }
        return bytes;
    }

    private static byte hexToByte(final String hexAsciiTwoNibbles) {
        final int hi = nib(hexAsciiTwoNibbles.charAt(0));
        final int lo = nib(hexAsciiTwoNibbles.charAt(1));
        return (byte)((hi << 4) | lo);
    }

    private static int nib(char hexChar) {
        final int n = Character.digit(hexChar, 16);
        if (n == -1) {
            throw new IllegalArgumentException("Invalid hex: "+ hexChar);
        }
        return n;
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
