package com.wrapper;

import com.wrapper.symmetric.builder.SymmetricBuilder;
import com.wrapper.symmetric.config.ErrorConfig;
import com.wrapper.symmetric.config.KeyStoreConfig;
import com.wrapper.symmetric.config.SymmetricConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;


@SpringBootApplication(scanBasePackages = SafencryptApplication.BASE_PACKAGE)
@ConfigurationPropertiesScan
@EnableConfigurationProperties({ErrorConfig.class, KeyStoreConfig.class, SymmetricConfig.class})
@AutoConfiguration
public class SafencryptApplication {

    protected static final String BASE_PACKAGE = "com.wrapper.symmetric";
    private static ApplicationContext applicationContext;

    public static void main(String[] args) {
        applicationContext = new AnnotationConfigApplicationContext(SafencryptApplication.class);
        for (String beanName : applicationContext.getBeanDefinitionNames()) {
            System.out.println(beanName);
        }

        SymmetricBuilder.encryption()
                .generateKey()
                .plaintext("sad".getBytes())
                .encrypt();
//        Security.addProvider(new BouncyCastleProvider());

    }

}