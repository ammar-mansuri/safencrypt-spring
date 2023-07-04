package com.wrapper.symmetric.config;

import com.wrapper.symmetric.builder.SymmetricBuilder;
import com.wrapper.symmetric.service.SymmetricImpl;
import com.wrapper.symmetric.service.SymmetricKeyStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/*@Configuration
@ConditionalOnClass({SymmetricImpl.class, SymmetricBuilder.class})
@EnableAutoConfiguration
@AutoConfigureBefore
@EnableConfigurationProperties({SymmetricConfig.class, ErrorConfig.class, KeyStoreConfig.class})*/
@AutoConfiguration
public class ConfigBeans {


    private final ErrorConfig errorConfig;
    private final SymmetricConfig symmetricConfig;

    private final KeyStoreConfig keyStoreConfig;

    @Autowired
    public ConfigBeans(ErrorConfig errorConfig, SymmetricConfig symmetricConfig, KeyStoreConfig keyStoreConfig) {
        this.errorConfig = errorConfig;
        this.symmetricConfig = symmetricConfig;
        this.keyStoreConfig = keyStoreConfig;
    }

    @Bean
    @ConditionalOnMissingBean
    public SymmetricImpl symmetricImpl() {
        return new SymmetricImpl(symmetricConfig, errorConfig);
    }

    @Bean
    @ConditionalOnMissingBean
    public SymmetricKeyStore symmetricKeyStore() {
        return new SymmetricKeyStore(keyStoreConfig, errorConfig);
    }

    @Bean
    @ConditionalOnMissingBean
    public SymmetricBuilder symmetricBuilder() {
        return new SymmetricBuilder(symmetricImpl(), errorConfig);
    }
}
