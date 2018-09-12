package nu.mine.mosher.security.password;

import org.junit.jupiter.api.Test;

import java.security.spec.InvalidKeySpecException;

import static nu.mine.mosher.security.password.StrongHash.*;
import static org.junit.jupiter.api.Assertions.*;

class StrongHashTest {
    private static final Class<? extends Throwable> NPE = NullPointerException.class;

    @Test
    void nominal() throws InvalidKeySpecException, HashedString.InvalidFormat {
        final String PASSWORD = "beige societal fleck johannes currency dill";
        final String hash = hash(PASSWORD);
        assertTrue(isPasswordValid(PASSWORD, hash),
            "correct password was found to be invalid");
    }

    @Test
    void negative() throws InvalidKeySpecException, HashedString.InvalidFormat {
        final String PASSWORD = "beige societal fleck johannes currency dill";
        final String hash = hash(PASSWORD);
        assertFalse(isPasswordValid("bad guess", hash),
            "incorrect password was found to be valid");
    }

    @Test
    void cannotHashEmptyPassword() {
        assertThrows(InvalidKeySpecException.class, () -> hash(""));
    }

    @Test
    void cannotHashNull() {
        assertThrows(NPE, () -> hash(null));
    }

    private static final String HASHED_EMPTY_PASSWORD = "101021:8FB39CDB3BAAB0E266352BBAD7C9472F:3DEB8539070548B82CE6BF6A1429F188EE1B1E72EBFC73B4B3A14F50B24B6F6A45FCF1311D92C09412FEC970B81A1577E67F9DE8F0B708FAEB12017177C3B0AA";
    @Test
    void emptyGuessIsNotValid() throws HashedString.InvalidFormat {
        assertFalse(isPasswordValid("", HASHED_EMPTY_PASSWORD),
            "empty guess was valid");
    }

    @Test
    void guessCannotBeNull() {
        assertThrows(NPE, () -> isPasswordValid(null, "1:00:00"));
    }

    @Test
    void storedHashCannotBeNull() {
        assertThrows(NPE, () -> isPasswordValid("foobar", null));
    }

    @Test
    void invalidStoredHashFormatZeroIterThrows() {
        assertThrows(HashedString.InvalidFormat.class, () -> isPasswordValid("foobar", "0:00:00"));
    }

    @Test
    void invalidStoredHashFormatThrows() {
        assertThrows(HashedString.InvalidFormat.class, () -> isPasswordValid("foobar", "hacked"));
    }

    @Test
    void emptyStoredHashFormatThrows() {
        assertThrows(HashedString.InvalidFormat.class, () -> isPasswordValid("foobar", ""));
    }

    @Test
    void storedHashWithManyFieldsThrows() {
        assertThrows(HashedString.InvalidFormat.class, () -> isPasswordValid("foobar", "1:00:00::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"));
    }

    @Test
    void hugeIterThrows() {
        assertThrows(HashedString.InvalidFormat.class, () -> isPasswordValid("foobar", Integer.toString(1 << 29)+":00:00"));
    }

    private static final String HASH_OF_TESTING_FROM_OLD_VERSION = "1001:E68F3071F2AD21FA9EE8A0116E2A2E9C:66D319C12AF0669F2DEAA7025AB588AC";
    @Test
    void backwardlyCompatible() throws HashedString.InvalidFormat {
        assertTrue(isPasswordValid("testing", HASH_OF_TESTING_FROM_OLD_VERSION),
            "correct password was found to be invalid using old hash algorithm");
    }

    @Test
    void cannotInstantiate() {
        assertThrows(IllegalStateException.class, StrongHash::new);
    }
}
