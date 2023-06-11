package com.wrapper;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.security.GeneralSecurityException;


@SpringBootApplication
//@ComponentScan(basePackages = WRAPPER_PACKAGE)
@ConfigurationPropertiesScan
public class Application {

    static final String WRAPPER_PACKAGE = "com.wrapper";

    public static void main(String[] args) throws GeneralSecurityException {

    }

}