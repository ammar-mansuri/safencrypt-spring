package com.wrapper.asymmetric.service;

import com.wrapper.asymmetric.config.ASymmetricConfig;
import com.wrapper.asymmetric.config.ASymmetricInteroperabilityConfig;
import org.springframework.stereotype.Service;

@Service
public class ASymmetricImpl {

    private final int GCM_TAG_LENGTH = 96;
    private final int GCM_IV_SIZE = 12;
    private final int REST_IV_SIZE = 16;

    private final ASymmetricInteroperabilityConfig aSymmetricInteroperabilityConfig;
    private final ASymmetricConfig aSymmetricConfig;


    public ASymmetricImpl(ASymmetricInteroperabilityConfig aSymmetricInteroperabilityConfig, ASymmetricConfig aSymmetricConfig) {
        this.aSymmetricInteroperabilityConfig = aSymmetricInteroperabilityConfig;
        this.aSymmetricConfig = aSymmetricConfig;
    }
}
