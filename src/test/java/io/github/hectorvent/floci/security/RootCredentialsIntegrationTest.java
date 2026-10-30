package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.github.hectorvent.floci.testutil.S3RequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    @Test
    void anAdministratorCannotClaimOrTouchTheRootMarker() {
        String admin = "marker-test-admin";
        rootIam("Action=CreateUser&Version=2010-05-08&UserName=" + admin).then().statusCode(200);
        rootIam("Action=AttachUserPolicy&Version=2010-05-08&UserName=" + admin
                + "&PolicyArn=" + URLEncoder.encode("arn:aws:iam::aws:policy/AdministratorAccess", StandardCharsets.UTF_8))
                .then().statusCode(200);
        String created = rootIam("Action=CreateAccessKey&Version=2010-05-08&UserName=" + admin)
                .then().statusCode(200).extract().asString();
        String adminKey = xmlElement(created, "AccessKeyId");
        String adminSecret = xmlElement(created, "SecretAccessKey");
        String marker = URLEncoder.encode("<root>", StandardCharsets.UTF_8);

        given()
            .filter(AwsRequestSigner.signedAs(adminKey, adminSecret, "iam"))
            .contentType(FORM)
            .body("Action=CreateUser&Version=2010-05-08&UserName=" + marker)
        .when()
            .post("/")
        .then()
            .statusCode(400)
            .body(containsString("ValidationError"));

        given()
            .filter(AwsRequestSigner.signedAs(adminKey, adminSecret, "iam"))
            .contentType(FORM)
            .body("Action=UpdateAccessKey&Version=2010-05-08&UserName=" + marker
                    + "&AccessKeyId=" + RootByEnvProfile.ROOT_ACCESS_KEY_ID + "&Status=Inactive")
        .when()
            .post("/")
        .then()
            .statusCode(404)
            .body(containsString("NoSuchEntity"));

        given()
            .filter(AwsRequestSigner.signedAs(
                    RootByEnvProfile.ROOT_ACCESS_KEY_ID, RootByEnvProfile.ROOT_SECRET_ACCESS_KEY, "sts"))
            .contentType(FORM)
            .body("Action=GetCallerIdentity&Version=2011-06-15")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body(containsString("<Arn>arn:aws:iam::000000000000:root</Arn>"));
    }

    private static Response rootIam(String body) {
        return given()
            .filter(AwsRequestSigner.signedAs(
                    RootByEnvProfile.ROOT_ACCESS_KEY_ID, RootByEnvProfile.ROOT_SECRET_ACCESS_KEY, "iam"))
            .contentType(FORM)
            .body(body)
        .when()
            .post("/");
    }

    private static String xmlElement(String xml, String name) {
        Matcher matcher = Pattern.compile("<" + name + ">([^<]+)</" + name + ">").matcher(xml);
        assertTrue(matcher.find(), "no " + name + " in " + xml);
        return matcher.group(1);
    }
}
