package com.auth.app.auth.service;

import com.auth.app.auth.jwt.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender javaMailSender;
    private final JwtService jwtService;

    public void sendRegistrationEmail(String email, String username) {
        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom("pjankovic03@gmail.com");
        message.setSubject("Registration");
        message.setText("Dear " + username + ", \nThank you for registering.");
        message.setTo(email);

        javaMailSender.send(message);
    }
    public void sendResetPasswordEmail(String email, String resetToken) {
        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom("pjankovic03@gmail.com");
        message.setSubject("Password reset");
        message.setText("Please click on following link " + buildResetLink(resetToken));
        message.setTo(email);

        javaMailSender.send(message);
    }
    private String buildResetLink(String resetToken) {
        String resetUrl = ""; // Specify the reset password URL
        return resetUrl + "?token=" + resetToken;
    }
}
