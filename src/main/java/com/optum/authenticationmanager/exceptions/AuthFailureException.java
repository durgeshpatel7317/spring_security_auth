package com.optum.authenticationmanager.exceptions;

public class AuthFailureException extends RuntimeException {
    public AuthFailureException() {
    }

    public AuthFailureException(String message) {
        super(message);
    }
}
