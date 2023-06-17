package com.wrapper.asymmetric.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Set;

@ConfigurationProperties(prefix = "crypto-config.symmetric-encryption")
public record ASymmetricConfig(String defaultAlgo, Set<String> algorithms) {
}
