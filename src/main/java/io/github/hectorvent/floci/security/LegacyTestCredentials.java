package io.github.hectorvent.floci.security;

/**
 * Whether the well-known {@code test} access key still signs requests. Unconfigured it does, so
 * classes built directly in unit tests keep the upstream behavior; {@link SecureModeInitializer}
 * sets it from {@code floci.auth.allow-test-credentials} at startup.
 */
public final class LegacyTestCredentials {

    private static final String LEGACY_ACCESS_KEY_ID = "test";

    private static volatile boolean allowed = true;

    private LegacyTestCredentials() {
    }

    public static boolean accepts(String accessKeyId) {
        return allowed && LEGACY_ACCESS_KEY_ID.equals(accessKeyId);
    }

    public static void configure(boolean allow) {
        allowed = allow;
    }

    public static void resetForTests() {
        allowed = true;
    }
}
