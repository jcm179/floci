package io.github.hectorvent.floci.security;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/** The secure-by-default settings of the main {@code application.yml}, over the permissive test configuration. */
public final class SecureProfile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "floci.services.iam.enforcement-enabled", "true",
                "floci.auth.validate-signatures", "true",
                "floci.services.s3.enforce-auth", "true",
                "floci.auth.allow-test-credentials", "false",
                "floci.auth.deny-unmapped-actions", "true",
                "floci.services.iam.seed-deployer-principal", "true");
    }
}
