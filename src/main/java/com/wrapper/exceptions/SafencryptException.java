package com.wrapper.exceptions;

public class SafencryptException extends Exception {

    public SafencryptException(final String message) {
        super(message);
    }

    SafencryptException(final String message, Exception ex) {
        super(message, ex);
    }
}
