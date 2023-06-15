package com.wrapper.symmetric.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Set;

@ConfigurationProperties(prefix = "crypto-config.symmetric-encryption")
public record SymmetricConfig(String defaultAlgo, Set<String> algorithms) {
}
