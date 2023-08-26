package com.auth.app.auth.controller;

import com.auth.app.auth.DTO.PasswordRequest;
import com.auth.app.auth.exceptions.InvalidPasswordException;
import com.auth.app.auth.exceptions.InvalidResetPasswordTokenException;
import com.auth.app.auth.exceptions.PasswordMismatchException;
import com.auth.app.auth.jwt.service.JwtService;
import com.auth.app.auth.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final JwtService jwtService;

    @PutMapping("/reset-password")
    @ResponseStatus(HttpStatus.OK)
    public void resetPassword(@RequestBody PasswordRequest request,@RequestParam("resetToken") String resetToken, @RequestHeader("Authorization") String header) throws PasswordMismatchException, InvalidPasswordException, InvalidResetPasswordTokenException {
        String token = header.substring(7);
        String username = jwtService.getUsername(token);

        userService.resetPassword(username, resetToken, request.password(), request.confirmPassword());
    }
    @GetMapping("/recovery")
    @ResponseStatus(HttpStatus.OK)
    public void sendResetPasswordEmail(@RequestHeader("Authorization") String header) {
        String token = header.substring(7);
        userService.sendResetPasswordEmail(token);
    }
}
