package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;

/** Applies the secure-by-default settings from {@link EmulatorConfig} as the application starts. */
@Startup
@ApplicationScoped
public class SecureModeInitializer {

    public SecureModeInitializer(EmulatorConfig config) {
        LegacyTestCredentials.configure(config.auth().allowTestCredentials());
    }
}
