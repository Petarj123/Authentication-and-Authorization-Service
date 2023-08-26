package com.auth.app.auth.exceptions;

public class InvalidPasswordException extends Exception {
    public InvalidPasswordException(String msg) {
        super(msg);
    }
}
