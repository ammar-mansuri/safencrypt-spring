package com.wrapper.symmetric.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "keystore-config")
public record KeyStoreConfig(String name, String password) {
}
