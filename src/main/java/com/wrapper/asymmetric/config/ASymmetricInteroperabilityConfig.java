package com.wrapper.asymmetric.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

@Validated
@ConfigurationProperties(prefix = "crypto-config.interoperability")
public record ASymmetricInteroperabilityConfig(Map<String, Details> languages) {

    public Details getlanguageDetails(String key) {
        return languages.get(key);
    }

    public record Details(String libraryProvider, Symmetric symmetric) {

        public record Symmetric(String defaultAlgo, String ivBytes,
                                String Resultant) {
        }
    }

}
