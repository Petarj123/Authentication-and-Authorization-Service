package com.auth.app.exceptions;

public class UnavailableEmailException extends Exception{

    public UnavailableEmailException(String message){
        super(message);
    }
}
