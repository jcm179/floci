package io.github.hectorvent.floci.security;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.HashMap;
import java.util.Map;

/**
 * {@link SecureProfile} with the root pair given the way {@code FLOCI_ROOT_ACCESS_KEY_ID} and
 * {@code FLOCI_ROOT_SECRET_ACCESS_KEY} give it, so a test can sign as the root it knows.
 */
public final class RootByEnvProfile implements QuarkusTestProfile {

    public static final String ROOT_ACCESS_KEY_ID = "AKIAROOTBYENVTEST001";
    public static final String ROOT_SECRET_ACCESS_KEY = "root-by-env-test-secret-0123456789abcdef";

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> overrides = new HashMap<>(new SecureProfile().getConfigOverrides());
        overrides.put("floci.auth.root.access-key-id", ROOT_ACCESS_KEY_ID);
        overrides.put("floci.auth.root.secret-access-key", ROOT_SECRET_ACCESS_KEY);
        return overrides;
    }
}
