package org.untp4j.did.web;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DidWebTest {

    @ParameterizedTest
    @CsvSource({
            "did:web:w3c-ccg.github.io, https://w3c-ccg.github.io/.well-known/did.json",
            "did:web:w3c-ccg.github.io:user:alice, https://w3c-ccg.github.io/user/alice/did.json",
            "did:web:example.com%3A3000:user:alice, https://example.com:3000/user/alice/did.json",
            "did:web:shlee1223.github.io:untp4j-demo, https://shlee1223.github.io/untp4j-demo/did.json"
    })
    void mapsToDocumentUrl(String did, String url) {
        assertThat(DidWeb.documentUrl(did)).hasToString(url);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "did:key:z6Mk",
            "did:web:",
            "did:web:example.com:",
            "did:web:example.com::a",
            "did:web:example.com:..:admin",
            "did:web:example.com:a%2Fb",
            "did:web:example.com%3A0",
            "did:web:example.com%3A99999",
            "did:web:Example.com",
            "did:web:exa_mple.com",
            "did:web:example.com@evil.com",
            "did:web:example.com%2Fevil"
    })
    void rejectsMalformedDids(String did) {
        assertThatThrownBy(() -> DidWeb.documentUrl(did)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void buildsDidFromHostAndPath() {
        assertThat(DidWeb.fromHostAndPath("shlee1223.github.io/untp4j-demo"))
                .isEqualTo("did:web:shlee1223.github.io:untp4j-demo");
    }
}
