package com.wrapper.symmetric.config;

import com.wrapper.exceptions.SafencryptException;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

@Validated
@ConfigurationProperties(prefix = "crypto-config.interoperability")
public record SymmetricInteroperabilityConfig(Map<String, Details> languages) {

    public Details languageDetails(String key) throws SafencryptException {
        return languages.entrySet().stream().filter(x -> x.getKey().equalsIgnoreCase(key))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElseThrow(() -> new SafencryptException("Unable to find Interoperability Configuration for the selected language"));
    }

    public record Details(String libraryProvider, Symmetric symmetric) {

        public record Symmetric(String defaultAlgo, Integer ivBytes, Integer tagLength, String resultant) {
        }
    }

}
