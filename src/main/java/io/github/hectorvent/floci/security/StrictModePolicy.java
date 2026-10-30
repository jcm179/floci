package io.github.hectorvent.floci.security;

import java.util.Set;

/**
 * Whether a signed request whose IAM action cannot be resolved is denied instead of allowed, for the
 * services where that gap would be a hole: S3, KMS, Secrets Manager, IAM and STS. Unconfigured it is
 * off, so classes built directly in unit tests keep the upstream behavior;
 * {@link SecureModeInitializer} sets it from {@code floci.auth.deny-unmapped-actions} at startup.
 */
public final class StrictModePolicy {

    private static final Set<String> STRICT_SCOPES = Set.of("s3", "kms", "secretsmanager", "iam", "sts");

    private static volatile boolean enabled;

    private StrictModePolicy() {
    }

    public static boolean deniesUnmapped(String credentialScope) {
        return enabled && credentialScope != null && STRICT_SCOPES.contains(credentialScope);
    }

    public static void configure(boolean enable) {
        enabled = enable;
    }

    public static void resetForTests() {
        enabled = false;
    }
}
