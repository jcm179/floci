package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.S3RequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

/**
 * With strict mode on, a signed request in the strict set whose route no rule maps is denied, while
 * unsigned calls, noAuth operations, per-key S3 POSTs and anonymous reads of a public bucket are not.
 */
@QuarkusTest
@TestProfile(RootByEnvProfile.class)
class StrictUnmappedActionIntegrationTest {

    private static final String PUBLIC_BUCKET = "strict-unmapped-public-bucket";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @AfterAll
    static void restoreDefaults() {
        LegacyTestCredentials.resetForTests();
        StrictModePolicy.resetForTests();
    }

    private static S3RequestSigner root() {
        return S3RequestSigner.signedAs(
                RootByEnvProfile.ROOT_ACCESS_KEY_ID, RootByEnvProfile.ROOT_SECRET_ACCESS_KEY);
    }

    @Test
    void aSignedPostOnAnObjectPathNoRuleMapsIsDenied() {
        given()
            .filter(root())
            .body("x")
        .when()
            .post("/strict-unmapped-bucket/some/key")
        .then()
            .statusCode(403)
            .body(containsString("AccessDenied"));
    }

    @Test
    void aSignedDeleteObjectsOnABucketIsNotDeniedByThePolicy() {
        given()
            .filter(root())
        .when()
            .put("/strict-unmapped-batch-bucket")
        .then()
            .statusCode(200);

        given()
            .filter(root())
            .contentType("application/xml")
            .body("<Delete><Object><Key>missing</Key></Object></Delete>")
        .when()
            .post("/strict-unmapped-batch-bucket?delete")
        .then()
            .statusCode(200);
    }

    @Test
    void assumeRoleWithWebIdentityWithoutASignatureIsNotRejectedByThePolicy() {
        given()
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "AssumeRoleWithWebIdentity")
            .formParam("Version", "2011-06-15")
            .formParam("RoleArn", "arn:aws:iam::000000000000:role/strict-web-identity-role")
            .formParam("RoleSessionName", "strict-session")
            .formParam("WebIdentityToken", "dummy-token")
        .when()
            .post("/")
        .then()
            .statusCode(400)
            .body(containsString("InvalidIdentityToken"))
            .body(not(containsString("AccessDenied")));
    }

    @Test
    void anAnonymousReadOfAnObjectInAPublicBucketStillWorks() {
        given().filter(root()).when().put("/" + PUBLIC_BUCKET).then().statusCode(200);
        given()
            .filter(root())
            .contentType("application/json")
            .body("""
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
                    "Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}
                    """.formatted(PUBLIC_BUCKET))
        .when()
            .put("/" + PUBLIC_BUCKET + "?policy")
        .then()
            .statusCode(204);
        given().filter(root()).body("public body").when().put("/" + PUBLIC_BUCKET + "/readme.txt")
            .then().statusCode(200);

        given()
        .when()
            .get("/" + PUBLIC_BUCKET + "/readme.txt")
        .then()
            .statusCode(200)
            .body(equalTo("public body"));
    }
}
