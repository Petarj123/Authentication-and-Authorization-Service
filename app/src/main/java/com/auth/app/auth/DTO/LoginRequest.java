package com.auth.app.auth.DTO;

public record LoginRequest(String usernameOrEmail, String password) {
}
