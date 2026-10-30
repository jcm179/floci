package io.github.hectorvent.floci.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StrictModePolicyTest {

    @AfterEach
    void restoreDefault() {
        StrictModePolicy.resetForTests();
    }

    @Test
    void unconfiguredItDeniesNothing() {
        assertFalse(StrictModePolicy.deniesUnmapped("s3"));
    }

    @Test
    void disabledItDeniesNothing() {
        StrictModePolicy.configure(false);
        for (String scope : List.of("s3", "kms", "secretsmanager", "iam", "sts")) {
            assertFalse(StrictModePolicy.deniesUnmapped(scope), scope);
        }
    }

    @Test
    void enabledItDeniesTheFiveStrictScopes() {
        StrictModePolicy.configure(true);
        for (String scope : List.of("s3", "kms", "secretsmanager", "iam", "sts")) {
            assertTrue(StrictModePolicy.deniesUnmapped(scope), scope);
        }
    }

    @Test
    void enabledItLeavesEveryOtherScopeAlone() {
        StrictModePolicy.configure(true);
        assertFalse(StrictModePolicy.deniesUnmapped("sqs"));
        assertFalse(StrictModePolicy.deniesUnmapped("lambda"));
        assertFalse(StrictModePolicy.deniesUnmapped(null));
    }

    @Test
    void resetReturnsToDisabled() {
        StrictModePolicy.configure(true);
        StrictModePolicy.resetForTests();
        assertFalse(StrictModePolicy.deniesUnmapped("s3"));
    }
}
