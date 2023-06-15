package com.wrapper.symmetric.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

@Validated
@ConfigurationProperties(prefix = "crypto-config.interoperability")
public record SymmetricInteroperabilityConfig(Map<String, Details> languages) {

    public Details getlanguageDetails(String key) {
        return languages.get(key);
    }

    public record Details(String libraryProvider, Symmetric symmetric) {

        public record Symmetric(String defaultAlgo, String encoding, String ivBytes,
                                String Resultant) {
        }
    }

}
