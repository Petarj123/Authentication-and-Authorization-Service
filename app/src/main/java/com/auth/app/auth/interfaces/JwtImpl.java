package com.auth.app.auth.interfaces;

import org.springframework.security.core.Authentication;

public interface JwtImpl {
    String generateToken(Authentication authentication);
    String getUsername(String token);
    String getEmail(String token);
    boolean validateToken(String token);

}
