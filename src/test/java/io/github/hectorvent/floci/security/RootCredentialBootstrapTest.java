package io.github.hectorvent.floci.security;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RootCredentialBootstrapTest {

    private static final KeyPair STORED_ROOT = new KeyPair("AKIASTOREDROOT000001", "stored-root-secret");
    private static final KeyPair STORED_DEPLOYER = new KeyPair("AKIASTOREDDEPLOYER01", "stored-deployer-secret");

    private final CredentialGenerator generator = new CredentialGenerator(new SecureRandom());

    @Test
    void generatesRootAndDeployerWhenNothingIsConfiguredOrStored() {
        RootCredentialBootstrap.Outcome outcome = RootCredentialBootstrap.resolve(
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), generator);

        assertTrue(outcome.rootGenerated());
        assertTrue(outcome.deployerGenerated());
        assertThat(outcome.root().accessKeyId(), matchesPattern("^AKIA[A-Z0-9]{16}$"));
        assertThat(outcome.root().secretAccessKey(), matchesPattern("^[A-Za-z0-9/+]{40}$"));
        assertThat(outcome.deployer().accessKeyId(), matchesPattern("^AKIA[A-Z0-9]{16}$"));
        assertNotEquals(outcome.root(), outcome.deployer());
    }

    @Test
    void reusesStoredPairsWhenTheEnvironmentIsUnset() {
        RootCredentialBootstrap.Outcome outcome = RootCredentialBootstrap.resolve(
                Optional.empty(), Optional.empty(), Optional.of(STORED_ROOT), Optional.of(STORED_DEPLOYER),
                generator);

        assertEquals(STORED_ROOT, outcome.root());
        assertFalse(outcome.rootGenerated());
        assertEquals(STORED_DEPLOYER, outcome.deployer());
        assertFalse(outcome.deployerGenerated());
    }

    @Test
    void environmentRootReplacesADifferentStoredRoot() {
        RootCredentialBootstrap.Outcome outcome = RootCredentialBootstrap.resolve(
                Optional.of("AKIAFROMENVIRONMENT1"), Optional.of("env-secret"),
                Optional.of(STORED_ROOT), Optional.of(STORED_DEPLOYER), generator);

        assertEquals(new KeyPair("AKIAFROMENVIRONMENT1", "env-secret"), outcome.root());
        assertFalse(outcome.rootGenerated());
    }

    @Test
    void onlyTheAccessKeyIdSetFailsNamingBothVariables() {
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> RootCredentialBootstrap.resolve(Optional.of("AKIAFROMENVIRONMENT1"), Optional.empty(),
                        Optional.empty(), Optional.empty(), generator));

        assertThat(failure.getMessage(), containsString("FLOCI_ROOT_SECRET_ACCESS_KEY"));
        assertThat(failure.getMessage(), containsString("FLOCI_ROOT_ACCESS_KEY_ID"));
    }

    @Test
    void blankValuesCountAsUnset() {
        RootCredentialBootstrap.Outcome outcome = RootCredentialBootstrap.resolve(
                Optional.of("  "), Optional.of(""), Optional.of(STORED_ROOT), Optional.empty(), generator);

        assertEquals(STORED_ROOT, outcome.root());
        assertFalse(outcome.rootGenerated());

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> RootCredentialBootstrap.resolve(Optional.of(" "), Optional.of("env-secret"),
                        Optional.empty(), Optional.empty(), generator));
        assertThat(failure.getMessage(), containsString("FLOCI_ROOT_ACCESS_KEY_ID"));
    }

    @Test
    void deployerIsNeverTakenFromTheEnvironment() {
        RootCredentialBootstrap.Outcome generated = RootCredentialBootstrap.resolve(
                Optional.of("AKIAFROMENVIRONMENT1"), Optional.of("env-secret"),
                Optional.empty(), Optional.empty(), generator);

        assertTrue(generated.deployerGenerated());
        assertNotEquals("AKIAFROMENVIRONMENT1", generated.deployer().accessKeyId());
        assertNotEquals("env-secret", generated.deployer().secretAccessKey());

        RootCredentialBootstrap.Outcome stored = RootCredentialBootstrap.resolve(
                Optional.of("AKIAFROMENVIRONMENT1"), Optional.of("env-secret"),
                Optional.empty(), Optional.of(STORED_DEPLOYER), generator);

        assertEquals(STORED_DEPLOYER, stored.deployer());
        assertFalse(stored.deployerGenerated());
    }
}
