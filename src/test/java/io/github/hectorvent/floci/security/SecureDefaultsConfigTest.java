package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class SecureDefaultsConfigTest {

    @Inject
    EmulatorConfig config;

    @Test
    void mainApplicationYmlIsSecure() throws IOException {
        Map<String, Object> root;
        try (Reader reader = Files.newBufferedReader(
                Path.of("src/main/resources/application.yml"), StandardCharsets.UTF_8)) {
            root = new Yaml().load(reader);
        }
        assertEquals(false, lookup(root, "floci", "auth", "allow-test-credentials"));
        assertEquals(true, lookup(root, "floci", "auth", "deny-unmapped-actions"));
        assertEquals(true, lookup(root, "floci", "auth", "validate-signatures"));
        assertEquals(true, lookup(root, "floci", "services", "iam", "enforcement-enabled"));
        assertEquals(true, lookup(root, "floci", "services", "iam", "seed-deployer-principal"));
        assertEquals(true, lookup(root, "floci", "services", "s3", "enforce-auth"));
        assertEquals("persistent", lookup(root, "floci", "storage", "mode"));
    }

    @Test
    void testProfileStaysPermissive() {
        assertTrue(config.auth().allowTestCredentials());
        assertFalse(config.auth().denyUnmappedActions());
        assertFalse(config.services().iam().enforcementEnabled());
    }

    @SuppressWarnings("unchecked")
    private static Object lookup(Map<String, Object> root, String... path) {
        Object current = root;
        for (String key : path) {
            assertTrue(current instanceof Map, "Missing YAML section before " + key);
            current = ((Map<String, Object>) current).get(key);
        }
        return current;
    }
}
