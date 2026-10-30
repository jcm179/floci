package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.AccessKey;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A persistent store from an earlier boot still holds {@code floci/floci}, a stale root and the
 * environment's root pair deactivated. After boot {@code floci/floci} signs nothing, the stale root
 * is gone, and the environment's root is active again: the recovery path the environment gives.
 */
@QuarkusTest
@TestProfile(LegacyDeployerKeyStoreProfile.class)
class LegacyDeployerKeyRemovedIntegrationTest {

    private static final String FORM = "application/x-www-form-urlencoded";

    @Inject
    IamService iamService;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void theStoredLegacyKeyIsDeletedAtBoot() {
        assertTrue(iamService.findAccessKey("floci").isEmpty());
    }

    @Test
    void theEnvironmentRootReplacesTheStaleRootAndIsActiveAgain() {
        assertTrue(iamService.findAccessKey(LegacyDeployerKeyStoreProfile.STALE_ROOT_ACCESS_KEY_ID).isEmpty());
        AccessKey root = iamService.findAccessKey(RootByEnvProfile.ROOT_ACCESS_KEY_ID).orElseThrow();
        assertEquals("Active", root.getStatus());
        assertEquals(IamService.ROOT_PRINCIPAL_MARKER, root.getUserName());
        assertTrue(iamService.isRootAccessKey(RootByEnvProfile.ROOT_ACCESS_KEY_ID));
    }

    @Test
    void signingWithTheStoredLegacyKeyIsRejected() {
        given()
            .filter(AwsRequestSigner.signedAs("floci", "floci", "sts"))
            .contentType(FORM)
            .body("Action=GetCallerIdentity&Version=2011-06-15")
        .when()
            .post("/")
        .then()
            .statusCode(403);
    }

    @Test
    void theRootStillSigns() {
        given()
            .filter(AwsRequestSigner.signedAs(
                    RootByEnvProfile.ROOT_ACCESS_KEY_ID, RootByEnvProfile.ROOT_SECRET_ACCESS_KEY, "sts"))
            .contentType(FORM)
            .body("Action=GetCallerIdentity&Version=2011-06-15")
        .when()
            .post("/")
        .then()
            .statusCode(200);
    }
}
