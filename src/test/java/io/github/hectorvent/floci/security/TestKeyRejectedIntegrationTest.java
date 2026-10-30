package io.github.hectorvent.floci.security;

import io.github.hectorvent.floci.core.common.Digests;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.github.hectorvent.floci.testutil.S3RequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/** With {@code allow-test-credentials=false}, the {@code test} key signs nothing, on any path that used to honor it. */
@QuarkusTest
@TestProfile(SecureProfile.class)
class TestKeyRejectedIntegrationTest {

    private static final String ACCESS_KEY = "test";
    private static final String SECRET_KEY = "test";
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
    void s3PresignedUrlSignedCorrectlyWithTheTestKeyIsRejectedAsAnUnknownKey() throws Exception {
        given()
            .urlEncodingEnabled(false)
        .when()
            .get(presignedGet("/test-key-rejected-bucket/object.txt"))
        .then()
            .statusCode(403)
            .body(containsString("<Code>InvalidAccessKeyId</Code>"));
    }

    @Test
    void s3PostPolicySignedCorrectlyWithTheTestKeyIsRejected() {
        String bucket = "test-key-rejected-post-bucket";
        String key = "post-object.txt";
        String policyBase64 = policyBase64(bucket, key);
        String amzDate = AMZ_DATE_FMT.format(Instant.now());
        String credential = ACCESS_KEY + "/" + amzDate.substring(0, 8) + "/us-east-1/s3/aws4_request";

        given()
            .multiPart("key", key)
            .multiPart("policy", policyBase64)
            .multiPart("x-amz-algorithm", "AWS4-HMAC-SHA256")
            .multiPart("x-amz-credential", credential)
            .multiPart("x-amz-date", amzDate)
            .multiPart("x-amz-signature", hex(hmacSha256(signingKey(amzDate.substring(0, 8)), policyBase64)))
            .multiPart("file", key, "should not be stored".getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
            .post("/" + bucket)
        .then()
            .statusCode(403);
    }

    /** A query-string SigV4 URL for {@code test/test}, signed the way an SDK presigner signs a GET. */
    private static String presignedGet(String path) throws Exception {
        String amzDate = AMZ_DATE_FMT.format(Instant.now());
        String date = amzDate.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        String host = "localhost:" + RestAssured.port;
        String canonicalQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=" + URLEncoder.encode(ACCESS_KEY + "/" + scope, StandardCharsets.UTF_8)
                + "&X-Amz-Date=" + amzDate
                + "&X-Amz-Expires=3600"
                + "&X-Amz-SignedHeaders=host";
        String canonicalRequest = "GET\n" + path + "\n" + canonicalQuery + "\n"
                + "host:" + host + "\n\n" + "host\n" + "UNSIGNED-PAYLOAD";
        String stringToSign = "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n"
                + Digests.sha256Hex(canonicalRequest);
        String signature = hex(hmacSha256(signingKey(date), stringToSign));
        return path + "?" + canonicalQuery + "&X-Amz-Signature=" + signature;
    }

    private static String policyBase64(String bucket, String key) {
        String expiration = Instant.now().plusSeconds(3600).atZone(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_INSTANT);
        String policy = """
                {"expiration": "%s", "conditions": [{"bucket": "%s"}, {"key": "%s"}]}
                """.formatted(expiration, bucket, key);
        return Base64.getEncoder().encodeToString(policy.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] signingKey(String date) throws Exception {
        byte[] kDate = hmacSha256(("AWS4" + SECRET_KEY).getBytes(StandardCharsets.UTF_8), date);
        byte[] kRegion = hmacSha256(kDate, "us-east-1");
        byte[] kService = hmacSha256(kRegion, "s3");
        return hmacSha256(kService, "aws4_request");
    }

    private static byte[] hmacSha256(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
