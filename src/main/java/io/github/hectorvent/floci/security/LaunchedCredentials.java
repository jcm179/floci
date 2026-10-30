package io.github.hectorvent.floci.security;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The credential a process or container that Floci launches itself must carry. Once the legacy
 * {@code test} key is rejected, the placeholder pair those workloads used to receive no longer
 * signs requests, so they get the internal pair instead. Every launch site asks this class, so
 * the condition lives in one place.
 */
public final class LaunchedCredentials {

    private static final String ACCESS_KEY_ID = "AWS_ACCESS_KEY_ID";
    private static final String SECRET_ACCESS_KEY = "AWS_SECRET_ACCESS_KEY";
    private static final String SESSION_TOKEN = "AWS_SESSION_TOKEN";
    private static final String LEGACY_ACCESS_KEY_ID = "test";

    private LaunchedCredentials() {
    }

    /** Present only when the internal pair is set and {@code test} is no longer accepted. */
    public static Optional<KeyPair> internalPair() {
        if (LegacyTestCredentials.accepts(LEGACY_ACCESS_KEY_ID)) {
            return Optional.empty();
        }
        return InternalCredentials.current();
    }

    /**
     * The credential variables as {@code NAME=value} entries: the internal pair without a session
     * token when it applies, otherwise the given legacy values. A null legacy token is omitted.
     */
    public static List<String> entries(String legacyAccessKeyId, String legacySecretAccessKey,
                                       String legacySessionToken) {
        List<String> entries = new ArrayList<>();
        variables(legacyAccessKeyId, legacySecretAccessKey, legacySessionToken)
                .forEach((name, value) -> entries.add(name + "=" + value));
        return entries;
    }

    /** Same as {@link #entries}, keyed by variable name. */
    public static Map<String, String> variables(String legacyAccessKeyId, String legacySecretAccessKey,
                                                String legacySessionToken) {
        Map<String, String> variables = new LinkedHashMap<>();
        Optional<KeyPair> internal = internalPair();
        if (internal.isPresent()) {
            variables.put(ACCESS_KEY_ID, internal.get().accessKeyId());
            variables.put(SECRET_ACCESS_KEY, internal.get().secretAccessKey());
            return variables;
        }
        variables.put(ACCESS_KEY_ID, legacyAccessKeyId);
        variables.put(SECRET_ACCESS_KEY, legacySecretAccessKey);
        if (legacySessionToken != null) {
            variables.put(SESSION_TOKEN, legacySessionToken);
        }
        return variables;
    }

    /**
     * Overrides the credential variables of a process environment with the internal pair and drops
     * an inherited session token. Leaves the environment untouched when the pair does not apply.
     */
    public static void applyTo(Map<String, String> environment) {
        Optional<KeyPair> internal = internalPair();
        if (internal.isPresent()) {
            environment.put(ACCESS_KEY_ID, internal.get().accessKeyId());
            environment.put(SECRET_ACCESS_KEY, internal.get().secretAccessKey());
            environment.remove(SESSION_TOKEN);
        }
    }
}
