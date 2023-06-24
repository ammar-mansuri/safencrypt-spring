package com.wrapper.exceptions;

import org.springframework.web.bind.annotation.ExceptionHandler;

public class SafencryptExceptionHandler {

    @ExceptionHandler(value = SafencryptException.class)
    public SafencryptException safencryptException(SafencryptException ex) throws SafencryptException {
        throw ex;
    }


    @ExceptionHandler(value = Exception.class)
    public SafencryptException unhandledException(Exception ex) throws SafencryptException {
        throw new SafencryptException(ex.getMessage(), ex);
    }


}
