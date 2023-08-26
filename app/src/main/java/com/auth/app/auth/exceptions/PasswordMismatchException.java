package com.auth.app.auth.exceptions;

public class PasswordMismatchException extends Exception{
    public PasswordMismatchException(String message){
        super(message);
    }
}
