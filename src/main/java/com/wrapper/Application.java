package com.wrapper;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.ApplicationContext;

import java.security.Security;


@SpringBootApplication(scanBasePackages = Application.BASE_PACKAGE)
@ConfigurationPropertiesScan
public class Application {

    protected static final String BASE_PACKAGE = "com.wrapper.symmetric";

    private static ApplicationContext applicationContext;


    public static void main(String[] args) {
        /*applicationContext = new AnnotationConfigApplicationContext(Application.class);
        for (String beanName : applicationContext.getBeanDefinitionNames()) {
            System.out.println(beanName);
        }*/

        Security.addProvider(new BouncyCastleProvider());

    }

}