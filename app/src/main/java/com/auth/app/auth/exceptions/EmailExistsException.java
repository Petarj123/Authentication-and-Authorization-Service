package com.auth.app.auth.exceptions;

public class EmailExistsException extends Exception {
    public EmailExistsException(String message) {
        super(message);
    }
}
