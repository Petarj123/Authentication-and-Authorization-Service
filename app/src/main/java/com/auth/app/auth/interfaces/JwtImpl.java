package com.auth.app.auth.interfaces;

import org.springframework.security.core.Authentication;

public interface JwtImpl {
    String generateToken(Authentication authentication);
    String generateRefreshToken(String username);
    String getUsername(String token);
    String getEmail(String token);
    boolean validateToken(String token);
    boolean validateRefreshToken(String token);

}
