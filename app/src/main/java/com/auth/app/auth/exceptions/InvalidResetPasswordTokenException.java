package com.auth.app.auth.exceptions;

public class InvalidResetPasswordTokenException extends Exception {
    public InvalidResetPasswordTokenException(String message) {
        super(message);
    }
}
