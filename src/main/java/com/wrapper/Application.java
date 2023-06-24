package com.wrapper;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;


@SpringBootApplication(scanBasePackages = Application.BASE_PACKAGE)
@ConfigurationPropertiesScan
public class Application {

    protected static final String BASE_PACKAGE = "com.wrapper";

}