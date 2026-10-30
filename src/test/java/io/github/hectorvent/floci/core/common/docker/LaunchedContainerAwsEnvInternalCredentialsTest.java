package io.github.hectorvent.floci.core.common.docker;

import io.github.hectorvent.floci.security.InternalCredentials;
import io.github.hectorvent.floci.security.KeyPair;
import io.github.hectorvent.floci.security.LegacyTestCredentials;
import io.github.hectorvent.floci.services.iam.model.SessionCreds;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class LaunchedContainerAwsEnvInternalCredentialsTest {

    private static final String INTERNAL_KEY = "AKIAAAAAAAAAAAAAAAAA";

    @AfterEach
    void resetStaticState() {
        InternalCredentials.clear();
        LegacyTestCredentials.resetForTests();
    }

    private LaunchedContainerAwsEnv awsEnv(UnaryOperator<String> hostEnv) {
        ContainerReachableEndpoint endpoint = mock(ContainerReachableEndpoint.class);
        when(endpoint.baseUrl()).thenReturn("http://localhost:4566");
        return new LaunchedContainerAwsEnv(endpoint, hostEnv);
    }

    @Test
    void injectsInternalPairWithoutSessionTokenWhenTestKeyIsRejected() {
        InternalCredentials.set(new KeyPair(INTERNAL_KEY, "s"));
        LegacyTestCredentials.configure(false);

        List<String> env = awsEnv(name -> null).sdkBaselineEnv("us-east-1", Optional.empty());

        assertTrue(env.contains("AWS_ACCESS_KEY_ID=" + INTERNAL_KEY));
        assertTrue(env.contains("AWS_SECRET_ACCESS_KEY=s"));
        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_SESSION_TOKEN=")));
    }

    @Test
    void internalPairWinsOverAmbientHostCredentialsAndOwnerAccount() {
        InternalCredentials.set(new KeyPair(INTERNAL_KEY, "s"));
        LegacyTestCredentials.configure(false);

        List<String> env = awsEnv(name -> "ambient").sdkBaselineEnv("us-east-1", Optional.empty(),
                Optional.empty(), "123456789012");

        assertTrue(env.contains("AWS_ACCESS_KEY_ID=" + INTERNAL_KEY));
        assertTrue(env.contains("AWS_SECRET_ACCESS_KEY=s"));
        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_SESSION_TOKEN=")));
    }

    @Test
    void injectedSessionCredentialsStillWinOverInternalPair() {
        InternalCredentials.set(new KeyPair(INTERNAL_KEY, "s"));
        LegacyTestCredentials.configure(false);

        List<String> env = awsEnv(name -> null).sdkBaselineEnv("us-east-1", Optional.empty(),
                Optional.of(new SessionCreds("ASIAROLE", "role-secret", "role-token")));

        assertTrue(env.contains("AWS_ACCESS_KEY_ID=ASIAROLE"));
        assertTrue(env.contains("AWS_SESSION_TOKEN=role-token"));
    }

    @Test
    void keepsTestCredentialsWhenLegacyKeyIsStillAccepted() {
        InternalCredentials.set(new KeyPair(INTERNAL_KEY, "s"));

        List<String> env = awsEnv(name -> null).sdkBaselineEnv("us-east-1", Optional.empty());

        assertTrue(env.contains("AWS_ACCESS_KEY_ID=test"));
        assertTrue(env.contains("AWS_SECRET_ACCESS_KEY=test"));
        assertTrue(env.contains("AWS_SESSION_TOKEN=test"));
    }

    @Test
    void keepsTestCredentialsWhenInternalPairIsUnset() {
        LegacyTestCredentials.configure(false);

        List<String> env = awsEnv(name -> null).sdkBaselineEnv("us-east-1", Optional.empty());

        assertTrue(env.contains("AWS_ACCESS_KEY_ID=test"));
        assertTrue(env.contains("AWS_SECRET_ACCESS_KEY=test"));
    }
}
