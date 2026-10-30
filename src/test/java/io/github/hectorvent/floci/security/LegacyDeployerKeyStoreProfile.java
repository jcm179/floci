package io.github.hectorvent.floci.security;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * {@link RootByEnvProfile} over persistent storage whose IAM access key file, written before the
 * application starts, holds what an earlier boot may have left: the public {@code floci/floci} key
 * an earlier version seeded (unprefixed, as a pre-multi-account store holds it), a stale root key
 * the environment now replaces, and the environment's own root pair stored deactivated. The
 * directory is new for each JVM, so a run never starts from the store a previous run cleaned.
 */
public final class LegacyDeployerKeyStoreProfile implements QuarkusTestProfile {

    static final Path STORAGE_DIR = Path.of("target", "legacy-deployer-key-it-" + ProcessHandle.current().pid());

    static final String STALE_ROOT_ACCESS_KEY_ID = "AKIASTALEROOT0000001";

    private static final String LEGACY_ACCESS_KEYS = """
            {
              "floci": {
                "accessKeyId": "floci",
                "secretAccessKey": "floci",
                "userName": "floci-deployer",
                "status": "Active"
              },
              "000000000000/%1$s": {
                "accessKeyId": "%1$s",
                "secretAccessKey": "stale-root-secret",
                "userName": "<root>",
                "status": "Active"
              },
              "000000000000/%2$s": {
                "accessKeyId": "%2$s",
                "secretAccessKey": "%3$s",
                "userName": "<root>",
                "status": "Inactive"
              }
            }
            """.formatted(STALE_ROOT_ACCESS_KEY_ID, RootByEnvProfile.ROOT_ACCESS_KEY_ID,
            RootByEnvProfile.ROOT_SECRET_ACCESS_KEY);

    static {
        try {
            // Written once: a later load of this class in another class loader must not put the
            // key back into a store the application has already cleaned.
            Path accessKeys = STORAGE_DIR.resolve("iam-access-keys.json");
            if (Files.notExists(accessKeys)) {
                Files.createDirectories(STORAGE_DIR);
                Files.writeString(accessKeys, LEGACY_ACCESS_KEYS);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> overrides = new HashMap<>(new RootByEnvProfile().getConfigOverrides());
        overrides.put("floci.storage.mode", "persistent");
        overrides.put("floci.storage.persistent-path", STORAGE_DIR.toAbsolutePath().toString());
        return overrides;
    }
}
