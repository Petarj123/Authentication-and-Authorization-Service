package com.auth.app.auth_controller;

import com.auth.app.auth.DTO.LoginResponse;
import com.auth.app.auth.exceptions.*;
import com.auth.app.auth.jwt.service.JwtService;
import com.auth.app.auth.service.AuthService;
import com.auth.app.auth.service.EmailService;
import com.auth.app.auth.user.model.SecureUser;
import com.auth.app.auth.user.model.User;
import com.auth.app.auth.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {
    @InjectMocks
    private AuthService authService;

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private EmailService emailService;

    @Test
    void shouldRegisterSuccessfully() throws PasswordMismatchException, InvalidPasswordException, UsernameExistsException, EmailExistsException, InvalidEmailException {
        String username = "User1";
        String email = "testemail1@gmail.com";
        String password = "Testpassword1!";

        when(userRepository.existsByUsername(username)).thenReturn(false);
        when(userRepository.existsByEmail(email)).thenReturn(false);

        authService.register(username, email, password, password);

        verify(userRepository, times(1)).save(any(User.class));
        verify(emailService, times(1)).sendRegistrationEmail(email, username);
    }
    @Test
    void shouldThrowUsernameExistsException() {
        String username = "User1";
        String email = "testemail1@gmail.com";
        String password = "Testpassword1!";

        when(userRepository.existsByUsername(username)).thenReturn(true);

        assertThrows(UsernameExistsException.class, () -> {
            authService.register(username, email, password, password);
        });
    }
    @Test
    void shouldThrowEmailExistsException() {
        String username = "User1";
        String email = "testemail1@gmail.com";
        String password = "Testpassword1!";

        when(userRepository.existsByEmail(email)).thenReturn(true);

        assertThrows(EmailExistsException.class, () -> {
            authService.register(username, email, password, password);
        });
    }
    @Test
    void shouldThrowInvalidPasswordException() {
        String username = "User1";
        String email = "testemail1@gmail.com";
        String password = "invalidpassword";

        when(userRepository.existsByUsername(username)).thenReturn(false);
        when(userRepository.existsByEmail(email)).thenReturn(false);

        assertThrows(InvalidPasswordException.class, () -> {
            authService.register(username, email, password, password);
        });
    }
    @Test
    void shouldThrowPasswordMismatchException() {
        String username = "User1";
        String email = "testemail1@gmail.com";
        String password = "Testpassword1!";

        when(userRepository.existsByUsername(username)).thenReturn(false);
        when(userRepository.existsByEmail(email)).thenReturn(false);

        assertThrows(PasswordMismatchException.class, () -> {
            authService.register(username, email, password, "wrongPassword");
        });
    }
    @Test
    public void shouldLoginSuccessfully() {
        // Given
        String usernameOrEmail = "testUser";
        String password = "password123";
        String mockToken = "mockedJwtToken";
        String mockRefreshToken = "mockedRefreshToken";

        Authentication authenticationMock = mock(Authentication.class);
        SecureUser secureUserMock = mock(SecureUser.class);
        User userMock = mock(User.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authenticationMock);

        when(authenticationMock.getPrincipal()).thenReturn(secureUserMock);
        when(secureUserMock.getUsername()).thenReturn(usernameOrEmail);

        when(userRepository.findByUsername(usernameOrEmail)).thenReturn(Optional.of(userMock));
        when(jwtService.generateToken(authenticationMock)).thenReturn(mockToken);
        when(jwtService.generateRefreshToken(usernameOrEmail)).thenReturn(mockRefreshToken);


        // When
        LoginResponse response = authService.login(usernameOrEmail, password);

        // Then
        assertNotNull(response);
        assertEquals(mockToken, response.token());
    }
}


