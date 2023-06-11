package com.wrapper.symmetric.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

import java.util.Set;

@ConstructorBinding
@ConfigurationProperties(prefix = "crypto-config.symmetric-encryption")
public record SymmetricEncryptionConfig(String defaultAlgo, Set<String> algorithms) {
}
