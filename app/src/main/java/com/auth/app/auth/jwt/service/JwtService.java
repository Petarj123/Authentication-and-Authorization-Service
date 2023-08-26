package com.auth.app.auth.jwt.service;

import com.auth.app.auth.interfaces.JwtImpl;
import com.auth.app.auth.user.model.SecureUser;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.List;

@Service
public class JwtService implements JwtImpl {
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final Long expiration;
    private final Key key;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.expiration}") Long expiration) {
        this.expiration = expiration;
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    @Override
    public String generateToken(Authentication authentication) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        SecureUser secureUser = (SecureUser) authentication.getPrincipal();
        String email = secureUser.getEmail();

        Date currentDate = new Date();
        Date expirationDate = new Date(currentDate.getTime() + expiration);
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .claim("email", email)
                .setIssuedAt(currentDate)
                .setExpiration(expirationDate)
                .signWith(key)
                .compact();
    }

    @Override
    public String getUsername(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    @Override
    public String getEmail(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("email", String.class);
    }

    @Override
    public boolean validateToken(String token) {
        try{
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parse(token);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
