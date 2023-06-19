package com.wrapper;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.ApplicationContext;


@SpringBootApplication(scanBasePackages = Application.BASE_PACKAGE)
@ConfigurationPropertiesScan
public class Application {

    protected static final String BASE_PACKAGE = "com.wrapper";

    private static ApplicationContext applicationContext;


    public static void main(String[] args) {

//        Security.addProvider(new BouncyCastleProvider());

    }

}