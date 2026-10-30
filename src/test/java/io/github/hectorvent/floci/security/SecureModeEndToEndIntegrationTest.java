package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.github.hectorvent.floci.testutil.S3RequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The secure-by-default settings end to end: the root creates a user whose policy allows one read
 * action on S3, KMS and Secrets Manager, the user performs that action and is denied the matching
 * write, and the legacy {@code test} and {@code floci} pairs sign nothing.
 */
@QuarkusTest
@TestProfile(RootByEnvProfile.class)
class SecureModeEndToEndIntegrationTest {

    private static final String FORM = "application/x-www-form-urlencoded";
    private static final String JSON_1_1 = "application/x-amz-json-1.1";
    private static final String BUCKET = "secure-mode-e2e-bucket";
    private static final String OBJECT_KEY = "report.txt";
    private static final String PLAINTEXT =
            Base64.getEncoder().encodeToString("secure-mode".getBytes(StandardCharsets.UTF_8));

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @AfterAll
    static void restoreDefaults() {
        LegacyTestCredentials.resetForTests();
        StrictModePolicy.resetForTests();
    }

    @Test
    void aUserAllowedOnlyGetObjectReadsAnObjectAndCannotWriteOne() {
        UserKey user = createUserWithPolicy("e2e-s3-reader", """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}"""
                .formatted(BUCKET));

        given().filter(rootS3()).when().put("/" + BUCKET).then().statusCode(200);
        given().filter(rootS3()).body("quarterly numbers")
            .when().put("/" + BUCKET + "/" + OBJECT_KEY).then().statusCode(200);

        given().filter(S3RequestSigner.signedAs(user.accessKeyId(), user.secretAccessKey()))
            .when().get("/" + BUCKET + "/" + OBJECT_KEY)
            .then().statusCode(200).body(equalTo("quarterly numbers"));

        given().filter(S3RequestSigner.signedAs(user.accessKeyId(), user.secretAccessKey()))
            .body("overwritten")
            .when().put("/" + BUCKET + "/" + OBJECT_KEY)
            .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));

        given().filter(rootS3())
            .when().get("/" + BUCKET + "/" + OBJECT_KEY)
            .then().statusCode(200).body(equalTo("quarterly numbers"));
    }

    @Test
    void aUserAllowedOnlyDecryptDecryptsAndCannotEncrypt() {
        String keyArn = rootJson("kms", "TrentService.CreateKey", "{}")
                .then().statusCode(200).extract().path("KeyMetadata.Arn");
        String ciphertext = rootJson("kms", "TrentService.Encrypt",
                "{\"KeyId\": \"" + keyArn + "\", \"Plaintext\": \"" + PLAINTEXT + "\"}")
                .then().statusCode(200).extract().path("CiphertextBlob");
        UserKey user = createUserWithPolicy("e2e-kms-decrypter", """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"kms:Decrypt","Resource":"%s"}]}"""
                .formatted(keyArn));

        userJson(user, "kms", "TrentService.Decrypt", "{\"CiphertextBlob\": \"" + ciphertext + "\"}")
            .then().statusCode(200).body("Plaintext", equalTo(PLAINTEXT));

        userJson(user, "kms", "TrentService.Encrypt",
                "{\"KeyId\": \"" + keyArn + "\", \"Plaintext\": \"" + PLAINTEXT + "\"}")
            .then().statusCode(400).body("__type", equalTo("AccessDeniedException"));
    }

    @Test
    void aUserAllowedOnlyGetSecretValueReadsASecretAndCannotWriteOne() {
        String secretArn = rootJson("secretsmanager", "secretsmanager.CreateSecret",
                "{\"Name\": \"e2e-secret\", \"SecretString\": \"s3cr3t\"}")
                .then().statusCode(200).extract().path("ARN");
        UserKey user = createUserWithPolicy("e2e-secret-reader", """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"%s"}]}"""
                .formatted(secretArn));

        userJson(user, "secretsmanager", "secretsmanager.GetSecretValue", "{\"SecretId\": \"e2e-secret\"}")
            .then().statusCode(200).body("SecretString", equalTo("s3cr3t"));

        userJson(user, "secretsmanager", "secretsmanager.PutSecretValue",
                "{\"SecretId\": \"e2e-secret\", \"SecretString\": \"changed\"}")
            .then().statusCode(400).body("__type", equalTo("AccessDeniedException"));
    }

    @Test
    void theLegacyTestAndFlociPairsAreRejected() {
        given().filter(S3RequestSigner.signedAs("test", "test"))
            .when().get("/")
            .then().statusCode(403);
        given().filter(S3RequestSigner.signedAs("floci", "floci"))
            .when().get("/")
            .then().statusCode(403);

        for (String legacy : new String[] {"test", "floci"}) {
            given()
                .filter(AwsRequestSigner.signedAs(legacy, legacy, "sts"))
                .contentType(FORM)
                .body("Action=GetCallerIdentity&Version=2011-06-15")
            .when()
                .post("/")
            .then()
                .statusCode(403)
                .body(not(containsString("<Arn>")));
        }
    }

    private static UserKey createUserWithPolicy(String userName, String policy) {
        rootIam("Action=CreateUser&Version=2010-05-08&UserName=" + userName).then().statusCode(200);
        rootIam("Action=PutUserPolicy&Version=2010-05-08&UserName=" + userName
                + "&PolicyName=inline&PolicyDocument=" + URLEncoder.encode(policy, StandardCharsets.UTF_8))
                .then().statusCode(200);
        String created = rootIam("Action=CreateAccessKey&Version=2010-05-08&UserName=" + userName)
                .then().statusCode(200).extract().asString();
        return new UserKey(xmlElement(created, "AccessKeyId"), xmlElement(created, "SecretAccessKey"));
    }

    private static S3RequestSigner rootS3() {
        return S3RequestSigner.signedAs(
                RootByEnvProfile.ROOT_ACCESS_KEY_ID, RootByEnvProfile.ROOT_SECRET_ACCESS_KEY);
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

    private static Response rootJson(String service, String target, String body) {
        return jsonCall(RootByEnvProfile.ROOT_ACCESS_KEY_ID, RootByEnvProfile.ROOT_SECRET_ACCESS_KEY,
                service, target, body);
    }

    private static Response userJson(UserKey user, String service, String target, String body) {
        return jsonCall(user.accessKeyId(), user.secretAccessKey(), service, target, body);
    }

    private static Response jsonCall(String accessKeyId, String secretAccessKey, String service, String target,
                                     String body) {
        return given()
            .filter(AwsRequestSigner.signedAs(accessKeyId, secretAccessKey, service))
            .header("X-Amz-Target", target)
            .contentType(JSON_1_1)
            .body(body)
        .when()
            .post("/");
    }

    private static String xmlElement(String xml, String name) {
        Matcher matcher = Pattern.compile("<" + name + ">([^<]+)</" + name + ">").matcher(xml);
        assertTrue(matcher.find(), "no " + name + " in " + xml);
        return matcher.group(1);
    }

    private record UserKey(String accessKeyId, String secretAccessKey) {
    }
}
