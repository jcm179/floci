package io.github.hectorvent.floci.security;

import java.util.Optional;

/**
 * The internal {@code floci-deployer} key pair, for the processes Floci launches itself (init hooks
 * and the containers of EC2, SageMaker and ECS). IAM sets it while seeding; it is never logged and
 * never handed to a person. Empty until set, and when the deployer principal is not seeded.
 */
public final class InternalCredentials {

    private static volatile KeyPair current;

    private InternalCredentials() {
    }

    public static Optional<KeyPair> current() {
        return Optional.ofNullable(current);
    }

    public static void set(KeyPair pair) {
        current = pair;
    }

    public static void clear() {
        current = null;
    }
}
