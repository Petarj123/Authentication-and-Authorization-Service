package com.auth.app.auth.DTO;

import lombok.Builder;


public record PasswordRequest(String password, String confirmPassword) {
}
