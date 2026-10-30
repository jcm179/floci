package io.github.hectorvent.floci.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LegacyTestCredentialsTest {

    @AfterEach
    void restoreDefault() {
        LegacyTestCredentials.resetForTests();
    }

    @Test
    void unconfiguredAcceptsTheTestKey() {
        LegacyTestCredentials.resetForTests();

        assertTrue(LegacyTestCredentials.accepts("test"));
    }

    @Test
    void disallowedRejectsTheTestKey() {
        LegacyTestCredentials.configure(false);

        assertFalse(LegacyTestCredentials.accepts("test"));
    }

    @Test
    void anyOtherKeyIsNeverAccepted() {
        assertFalse(LegacyTestCredentials.accepts("AKIAXXXXXXXXXXXXXXXX"));
        assertFalse(LegacyTestCredentials.accepts(null));
        LegacyTestCredentials.configure(false);
        assertFalse(LegacyTestCredentials.accepts("AKIAXXXXXXXXXXXXXXXX"));
    }

    @Test
    void resetRestoresTheDefault() {
        LegacyTestCredentials.configure(false);
        LegacyTestCredentials.resetForTests();

        assertTrue(LegacyTestCredentials.accepts("test"));
    }
}
