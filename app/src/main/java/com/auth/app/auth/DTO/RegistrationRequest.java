package com.auth.app.auth.DTO;

public record RegistrationRequest(String username, String email, String password, String confirmPassword) {
}
