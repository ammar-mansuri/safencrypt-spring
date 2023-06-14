package com.wrapper.symmetric.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

@Validated
@ConfigurationProperties(prefix = "crypto-config.interoperability")
public record InteroperabilitySymmetricEncryptionConfig(Map<String, Details> languages) {

    public record Details(String libraryProvider, Symmetric symmetric) {

        public record Symmetric(String defaultAlgo, String encoding, String keyBytes, String ivBytes,
                                String Resultant) {
        }
    }

}
