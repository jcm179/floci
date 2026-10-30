package io.github.hectorvent.floci.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InitHookCredentialsTest {

    private static final String INTERNAL_KEY = "AKIAAAAAAAAAAAAAAAAA";

    @AfterEach
    void resetStaticState() {
        InternalCredentials.clear();
        LegacyTestCredentials.resetForTests();
    }

    private Map<String, String> inheritedEnvironment() {
        Map<String, String> environment = new HashMap<>();
        environment.put("AWS_ACCESS_KEY_ID", "test");
        environment.put("AWS_SECRET_ACCESS_KEY", "test");
        environment.put("AWS_SESSION_TOKEN", "inherited");
        environment.put("PATH", "/usr/bin");
        return environment;
    }

    @Test
    void hookEnvironmentCarriesInternalPairAndDropsSessionToken() {
        InternalCredentials.set(new KeyPair(INTERNAL_KEY, "s"));
        LegacyTestCredentials.configure(false);
        Map<String, String> environment = inheritedEnvironment();

        LaunchedCredentials.applyTo(environment);

        assertEquals(INTERNAL_KEY, environment.get("AWS_ACCESS_KEY_ID"));
        assertEquals("s", environment.get("AWS_SECRET_ACCESS_KEY"));
        assertFalse(environment.containsKey("AWS_SESSION_TOKEN"));
        assertEquals("/usr/bin", environment.get("PATH"));
    }

    @Test
    void hookEnvironmentIsUntouchedWhenTestKeyIsStillAccepted() {
        InternalCredentials.set(new KeyPair(INTERNAL_KEY, "s"));
        Map<String, String> environment = inheritedEnvironment();

        LaunchedCredentials.applyTo(environment);

        assertEquals(inheritedEnvironment(), environment);
    }

    @Test
    void hookEnvironmentIsUntouchedWhenInternalPairIsUnset() {
        LegacyTestCredentials.configure(false);
        Map<String, String> environment = inheritedEnvironment();

        LaunchedCredentials.applyTo(environment);

        assertEquals(inheritedEnvironment(), environment);
    }

    @Test
    void entriesUseInternalPairOnlyWhenItApplies() {
        InternalCredentials.set(new KeyPair(INTERNAL_KEY, "s"));
        LegacyTestCredentials.configure(false);

        assertEquals(List.of("AWS_ACCESS_KEY_ID=" + INTERNAL_KEY, "AWS_SECRET_ACCESS_KEY=s"),
                LaunchedCredentials.entries("test", "test", "test"));

        LegacyTestCredentials.configure(true);

        assertEquals(List.of("AWS_ACCESS_KEY_ID=test", "AWS_SECRET_ACCESS_KEY=test", "AWS_SESSION_TOKEN=test"),
                LaunchedCredentials.entries("test", "test", "test"));
    }

    @Test
    void variablesOmitNullLegacySessionToken() {
        Map<String, String> variables = LaunchedCredentials.variables("test", "test", null);

        assertEquals(2, variables.size());
        assertTrue(variables.containsKey("AWS_ACCESS_KEY_ID"));
        assertFalse(variables.containsKey("AWS_SESSION_TOKEN"));
    }
}
