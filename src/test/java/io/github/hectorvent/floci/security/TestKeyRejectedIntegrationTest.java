package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.github.hectorvent.floci.testutil.S3RequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import static io.restassured.RestAssured.given;

/** With {@code allow-test-credentials=false}, the {@code test} key signs nothing, on any path that used to honor it. */
@QuarkusTest
@TestProfile(SecureProfile.class)
class TestKeyRejectedIntegrationTest {

    private static final String JSON_1_0 = "application/x-amz-json-1.0";
    private static final DateTimeFormatter AMZ_DATE_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @AfterAll
    static void restoreLegacyDefault() {
        LegacyTestCredentials.resetForTests();
    }

    @Test
    void sqsRequestSignedWithTheTestKeyIsRejected() {
        given()
            .filter(AwsRequestSigner.signedAs("test", "test", "sqs"))
            .contentType(JSON_1_0)
            .header("X-Amz-Target", "AmazonSQS.ListQueues")
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(403);
    }

    @Test
    void s3ListBucketsSignedWithTheTestKeyIsRejected() {
        given()
            .filter(S3RequestSigner.signedAs("test", "test"))
        .when()
            .get("/")
        .then()
            .statusCode(403);
    }

    @Test
    void s3PresignedUrlWithTheTestKeyIsRejected() {
        String amzDate = AMZ_DATE_FMT.format(Instant.now());
        String credential = URLEncoder.encode(
                "test/" + amzDate.substring(0, 8) + "/us-east-1/s3/aws4_request", StandardCharsets.UTF_8);
        given()
            .urlEncodingEnabled(false)
        .when()
            .get("/some-bucket/some-key"
                    + "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                    + "&X-Amz-Credential=" + credential
                    + "&X-Amz-Date=" + amzDate
                    + "&X-Amz-Expires=3600"
                    + "&X-Amz-SignedHeaders=host"
                    + "&X-Amz-Signature=fakesig")
        .then()
            .statusCode(403);
    }
}
