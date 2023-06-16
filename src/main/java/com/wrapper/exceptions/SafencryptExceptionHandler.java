package com.wrapper.exceptions;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class SafencryptExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(SafencryptException.class)
    public SafencryptException safeException(SafencryptException ex) throws SafencryptException {
        throw ex;
    }


    @ExceptionHandler(Exception.class)
    public SafencryptException unhandledException(Exception ex) throws SafencryptException {
        throw new SafencryptException(ex.getMessage(), ex);
    }


}
