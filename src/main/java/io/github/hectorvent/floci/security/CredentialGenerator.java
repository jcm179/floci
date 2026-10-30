package io.github.hectorvent.floci.security;

import java.security.SecureRandom;

public class CredentialGenerator {

    private static final String ACCESS_KEY_PREFIX = "AKIA";
    private static final int ACCESS_KEY_LENGTH = 20;
    private static final int SECRET_KEY_LENGTH = 40;
    private static final String ACCESS_KEY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final String SECRET_KEY_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";

    private final SecureRandom random;

    public CredentialGenerator(SecureRandom random) {
        this.random = random;
    }

    public String newAccessKeyId() {
        return ACCESS_KEY_PREFIX + randomString(ACCESS_KEY_ALPHABET, ACCESS_KEY_LENGTH - ACCESS_KEY_PREFIX.length());
    }

    public String newSecretAccessKey() {
        return randomString(SECRET_KEY_ALPHABET, SECRET_KEY_LENGTH);
    }

    private String randomString(String alphabet, int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return sb.toString();
    }
}
