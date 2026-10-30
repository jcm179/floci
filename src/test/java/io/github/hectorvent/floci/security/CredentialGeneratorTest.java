package io.github.hectorvent.floci.security;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialGeneratorTest {

    private final CredentialGenerator generator = new CredentialGenerator(new SecureRandom());

    @Test
    void accessKeyIdHasAkiaPrefixAndTwentyCharacters() {
        assertThat(generator.newAccessKeyId(), matchesPattern("^AKIA[A-Z0-9]{16}$"));
    }

    @Test
    void secretAccessKeyHasFortyBase64Characters() {
        assertThat(generator.newSecretAccessKey(), matchesPattern("^[A-Za-z0-9/+]{40}$"));
    }

    @Test
    void thousandAccessKeyIdsAreUnique() {
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            ids.add(generator.newAccessKeyId());
        }
        assertEquals(1000, ids.size());
    }
}
