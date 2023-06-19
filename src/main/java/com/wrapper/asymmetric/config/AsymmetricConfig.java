package com.wrapper.asymmetric.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Set;

@ConfigurationProperties(prefix = "crypto-config.asymmetric-encryption")
public record AsymmetricConfig(String defaultAlgo, Set<String> algorithms) {
}
