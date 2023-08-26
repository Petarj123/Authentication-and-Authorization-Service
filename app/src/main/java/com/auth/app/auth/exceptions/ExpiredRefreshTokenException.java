package com.auth.app.auth.exceptions;

public class ExpiredRefreshTokenException extends Exception{

    public ExpiredRefreshTokenException(String message) {
        super(message);
    }
}
