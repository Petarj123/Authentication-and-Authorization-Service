package com.auth.app.auth.user.service;

import com.auth.app.auth.exceptions.InvalidPasswordException;
import com.auth.app.auth.exceptions.InvalidResetPasswordTokenException;
import com.auth.app.auth.exceptions.PasswordMismatchException;
import com.auth.app.auth.jwt.service.JwtService;
import com.auth.app.auth.service.EmailService;
import com.auth.app.auth.user.model.User;
import com.auth.app.auth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private static final String PASSWORD_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,}$";

    public void resetPassword(String usernameOrEmail, String resetToken, String password, String confirmPassword) throws PasswordMismatchException, InvalidPasswordException, InvalidResetPasswordTokenException {
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail).orElseThrow(() -> new UsernameNotFoundException("Could not find user."));

        if (!resetToken.equals(user.getResetPasswordToken())) {
            throw new InvalidResetPasswordTokenException("Reset password tokens do not match!");
        }
        if (!Pattern.matches(PASSWORD_REGEX, password)) {
            throw new InvalidPasswordException("Password does not meet the requirements");
        }

        if (!password.equals(confirmPassword)){
            throw new PasswordMismatchException("Passwords do not match");
        }
        user.setPassword(passwordEncoder.encode(password));

        userRepository.save(user);
    }
    public void sendResetPasswordEmail(String token) {
        String username = jwtService.getUsername(token);

        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found."));

        user.setResetPasswordToken(generatePasswordRefreshToken());

        userRepository.save(user);

        emailService.sendResetPasswordEmail(user.getEmail(), user.getResetPasswordToken());
    }
    private String generatePasswordRefreshToken() {
        return UUID.randomUUID().toString();
    }

}
