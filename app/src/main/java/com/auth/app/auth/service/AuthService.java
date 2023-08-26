package com.auth.app.auth.service;


import com.auth.app.auth.DTO.LoginResponse;
import com.auth.app.auth.exceptions.*;
import com.auth.app.auth.jwt.service.JwtService;
import com.auth.app.auth.user.model.Role;
import com.auth.app.auth.user.model.SecureUser;
import com.auth.app.auth.user.model.User;
import com.auth.app.auth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class AuthService {
    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@(.+)$";
    private static final String PASSWORD_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,}$";
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public LoginResponse login(String usernameOrEmail, String password) {

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                usernameOrEmail, password));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        manageUserRefreshToken(authentication);

        return LoginResponse.builder()
                .token(jwtService.generateToken(authentication))
                .build();
    }
    public void register(String username, String email, String password, String confirmPassword) throws PasswordMismatchException, InvalidPasswordException, InvalidEmailException, UsernameExistsException, EmailExistsException {

        if (userRepository.existsByUsername(username)) {
            throw new UsernameExistsException("Username already exists");
        } else if (userRepository.existsByEmail(email)) {
            throw new EmailExistsException("Email already exists");
        }

        if (!Pattern.matches(EMAIL_REGEX, email)) {
            throw new InvalidEmailException("Invalid email format");
        }

        if (!Pattern.matches(PASSWORD_REGEX, password)) {
            throw new InvalidPasswordException("Password does not meet the requirements");
        }

        if (!password.equals(confirmPassword)){
            throw new PasswordMismatchException("Passwords do not match");
        }

        User user = createUser(username, email, password);

        userRepository.save(user);
    }
    private User createUser(String username, String email, String password) {
        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .roles(new HashSet<>())
                .createdAt(new Date())
                .refreshToken(null)
                .isLocked(false)
                .build();
        user.setRoles(new HashSet<>(List.of(Role.USER)));
        return user;
    }

    private void manageUserRefreshToken(Authentication authentication) {
        SecureUser secureUser = (SecureUser) authentication.getPrincipal();
        User user = userRepository.findByUsername(secureUser.getUsername()).orElseThrow();

        boolean shouldGenerateNewToken = false;

        if (user.getRefreshToken() == null || user.getRefreshToken().isEmpty()) {
            // No refresh token set
            shouldGenerateNewToken = true;
        } else {
            // Check if the token has expired
            try {
                if (!jwtService.validateRefreshToken(user.getRefreshToken())) {
                    Date refreshTokenExpiry = jwtService.extractExpirationDate(user.getRefreshToken());
                    if (refreshTokenExpiry.before(new Date())) {
                        shouldGenerateNewToken = true;  // Refresh token has expired
                    }
                }
            } catch (Exception e) {
                shouldGenerateNewToken = true;
            }
        }

        if (shouldGenerateNewToken) {
            String newRefreshToken = jwtService.generateRefreshToken(secureUser.getUsername());
            user.setRefreshToken(newRefreshToken);
            userRepository.save(user);
        }
    }


}
