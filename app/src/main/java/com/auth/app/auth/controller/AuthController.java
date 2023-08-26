package com.auth.app.auth.controller;

import com.auth.app.auth.DTO.LoginRequest;
import com.auth.app.auth.DTO.LoginResponse;
import com.auth.app.auth.DTO.RegistrationRequest;
import com.auth.app.auth.exceptions.*;
import com.auth.app.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public LoginResponse login(@RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest.usernameOrEmail(), loginRequest.password());
    }
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public void register(@RequestBody RegistrationRequest request) throws PasswordMismatchException, InvalidPasswordException, UsernameExistsException, EmailExistsException, InvalidEmailException {
        authService.register(request.username(), request.email(), request.password(), request.confirmPassword());
    }
}
