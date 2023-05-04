package com.auth.app.DTO;

import lombok.Data;

public record AuthenticationRequest(String email, String password) {
}
