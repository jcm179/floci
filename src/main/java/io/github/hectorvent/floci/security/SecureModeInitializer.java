package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.ServiceConfigAccess;
import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.interceptor.Interceptor;
import org.jboss.logging.Logger;

/** Applies the secure-by-default settings from {@link EmulatorConfig} as the application starts. */
@Startup(Interceptor.Priority.PLATFORM_BEFORE)
@ApplicationScoped
public class SecureModeInitializer {

    private static final Logger LOG = Logger.getLogger(SecureModeInitializer.class);

    public SecureModeInitializer(EmulatorConfig config, ServiceConfigAccess serviceConfigAccess) {
        LegacyTestCredentials.configure(config.auth().allowTestCredentials());
        StrictModePolicy.configure(config.auth().denyUnmappedActions());
        if (config.services().iam().enforcementEnabled()
                && "memory".equalsIgnoreCase(serviceConfigAccess.storageMode("iam"))) {
            LOG.warn("IAM enforcement is on with memory storage: the root credentials are lost on every"
                    + " restart. Use persistent storage, or set FLOCI_ROOT_ACCESS_KEY_ID and"
                    + " FLOCI_ROOT_SECRET_ACCESS_KEY.");
        }
    }
}
