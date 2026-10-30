package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.github.hectorvent.floci.testutil.S3RequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With enforcement on, the root given by environment signs as the account root and may do
 * anything, the internal deployer pair signs for what Floci launches, and {@code floci/floci} signs
 * nothing.
 */
@QuarkusTest
@TestProfile(RootByEnvProfile.class)
class RootCredentialsIntegrationTest {

    private static final String FORM = "application/x-www-form-urlencoded";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @AfterAll
    static void restoreLegacyDefault() {
        LegacyTestCredentials.resetForTests();
    }

    @Test
    void getCallerIdentitySignedWithTheRootAnswersTheAccountRootArn() {
        given()
            .filter(AwsRequestSigner.signedAs(
                    RootByEnvProfile.ROOT_ACCESS_KEY_ID, RootByEnvProfile.ROOT_SECRET_ACCESS_KEY, "sts"))
            .contentType(FORM)
            .body("Action=GetCallerIdentity&Version=2011-06-15")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body(containsString("<Arn>arn:aws:iam::000000000000:root</Arn>"))
            .body(containsString("<Account>000000000000</Account>"));
    }

    @Test
    void theRootCanCreateAnIamUser() {
        given()
            .filter(AwsRequestSigner.signedAs(
                    RootByEnvProfile.ROOT_ACCESS_KEY_ID, RootByEnvProfile.ROOT_SECRET_ACCESS_KEY, "iam"))
            .contentType(FORM)
            .body("Action=CreateUser&Version=2010-05-08&UserName=created-by-root")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body(containsString("<UserName>created-by-root</UserName>"));
    }

    @Test
    void theLegacyFlociPairIsRejected() {
        given()
            .filter(AwsRequestSigner.signedAs("floci", "floci", "sts"))
            .contentType(FORM)
            .body("Action=GetCallerIdentity&Version=2011-06-15")
        .when()
            .post("/")
        .then()
            .statusCode(403)
            .body(not(containsString("<Arn>")));
    }

    @Test
    void theInternalPairCanCreateAnS3Bucket() {
        KeyPair internal = InternalCredentials.current().orElseThrow();
        assertTrue(internal.accessKeyId().startsWith("AKIA"));
        assertNotEquals(RootByEnvProfile.ROOT_ACCESS_KEY_ID, internal.accessKeyId());

        given()
            .filter(S3RequestSigner.signedAs(internal.accessKeyId(), internal.secretAccessKey()))
        .when()
            .put("/root-credentials-internal-bucket")
        .then()
            .statusCode(200);
    }
}
