package io.github.hectorvent.floci.security;

import java.util.Optional;

/**
 * Decides, on each start, which root key pair and which internal deployer key pair IAM holds.
 *
 * <p>The root comes from {@code FLOCI_ROOT_ACCESS_KEY_ID} and {@code FLOCI_ROOT_SECRET_ACCESS_KEY}
 * when both are set, replacing any stored root; otherwise the stored root is reused; otherwise a new
 * one is generated. The deployer is never taken from the environment: the stored pair is reused, or
 * a new one is generated. A blank value counts as not set, and only one of the two root variables
 * set is a configuration error.
 */
public final class RootCredentialBootstrap {

    static final String ENV_ACCESS_KEY_ID = "FLOCI_ROOT_ACCESS_KEY_ID";
    static final String ENV_SECRET_ACCESS_KEY = "FLOCI_ROOT_SECRET_ACCESS_KEY";

    private RootCredentialBootstrap() {
    }

    /** The pairs to hold, and whether each was generated on this start. */
    public record Outcome(KeyPair root, boolean rootGenerated, KeyPair deployer, boolean deployerGenerated) {
    }

    public static Outcome resolve(Optional<String> envAccessKeyId,
                                  Optional<String> envSecretAccessKey,
                                  Optional<KeyPair> storedRoot,
                                  Optional<KeyPair> storedDeployer,
                                  CredentialGenerator generator) {
        Optional<String> accessKeyId = nonBlank(envAccessKeyId);
        Optional<String> secretAccessKey = nonBlank(envSecretAccessKey);
        if (accessKeyId.isPresent() != secretAccessKey.isPresent()) {
            throw new IllegalStateException("Root credentials are half configured: set both "
                    + ENV_ACCESS_KEY_ID + " and " + ENV_SECRET_ACCESS_KEY + ", or neither");
        }

        KeyPair root;
        boolean rootGenerated = false;
        if (accessKeyId.isPresent()) {
            root = new KeyPair(accessKeyId.get(), secretAccessKey.get());
        } else if (storedRoot.isPresent()) {
            root = storedRoot.get();
        } else {
            root = generate(generator);
            rootGenerated = true;
        }

        KeyPair deployer;
        boolean deployerGenerated = false;
        if (storedDeployer.isPresent()) {
            deployer = storedDeployer.get();
        } else {
            deployer = generate(generator);
            deployerGenerated = true;
        }
        return new Outcome(root, rootGenerated, deployer, deployerGenerated);
    }

    private static KeyPair generate(CredentialGenerator generator) {
        return new KeyPair(generator.newAccessKeyId(), generator.newSecretAccessKey());
    }

    private static Optional<String> nonBlank(Optional<String> value) {
        return value == null ? Optional.empty() : value.filter(v -> !v.isBlank());
    }
}
