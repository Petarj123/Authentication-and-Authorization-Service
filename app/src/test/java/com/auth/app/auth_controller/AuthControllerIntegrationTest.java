package com.auth.app.auth_controller;

import com.auth.app.auth.DTO.LoginRequest;
import com.auth.app.auth.DTO.RegistrationRequest;
import com.auth.app.auth.exceptions.InvalidEmailException;
import com.auth.app.auth.exceptions.InvalidPasswordException;
import com.auth.app.auth.exceptions.PasswordMismatchException;
import com.auth.app.auth.exceptions.UsernameExistsException;
import com.auth.app.auth.service.AuthService;
import com.auth.app.auth.user.model.Role;
import com.auth.app.auth.user.model.User;
import com.auth.app.auth.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerIntegrationTest {
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private AuthService authService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void tearDown() {
        saveUser();
    }

    @AfterEach
    void after() {
        userRepository.findByUsernameOrEmail("Petarj12345213", "Petarj12345213").ifPresent(user -> userRepository.deleteById(user.getId()));
        userRepository.findByUsernameOrEmail("Petarj12345", "Petarj12345").ifPresent(user -> userRepository.deleteById(user.getId()));

    }

    @Test
    void registerUser_success_shouldReturn201() throws Exception {
        RegistrationRequest request = new RegistrationRequest("Petarj12345213", "izmisljenemail1@gmail.com", "Testsifra123#", "Testsifra123#");

        String requestBody = mapper.writeValueAsString(request);
        System.out.println(requestBody);
        mockMvc.perform(post("/api/auth/register").contentType("application/json").content(requestBody)).andExpect(status().isCreated());
    }
    @Test
    void testRegisterUser_passwordMismatch_shouldReturn400() throws Exception {
        RegistrationRequest request = new RegistrationRequest("Petarj12345213", "izmisljenemail1@gmail.com", "Testsifra1223#", "Testsifra123#");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());

        assertThrows(PasswordMismatchException.class, () -> {
            authService.register(request.username(), request.email(), request.password(), request.confirmPassword());
        });
    }

    @Test
    void testRegisterUser_invalidPassword_shouldReturn400() throws Exception {
        RegistrationRequest request = new RegistrationRequest("Petarj12345213", "izmisljenemail1@gmail.com", "Test", "Test");
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        assertThrows(InvalidPasswordException.class, () -> {
            authService.register(request.username(), request.email(), request.password(), request.confirmPassword());
        });
    }
    @Test
    void testRegisterUser_usernameExists_shouldReturn409() throws Exception {
        RegistrationRequest request = new RegistrationRequest("Petarj123", "izmisljenemail1@gmail.com", "Testsifra1223#", "Testsifra123#");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isConflict());

        assertThrows(UsernameExistsException.class, () -> {
            authService.register(request.username(), request.email(), request.password(), request.confirmPassword());
        });
    }
    @Test
    void testRegisterUser_invalidEmail_shouldReturn409() throws Exception {
       RegistrationRequest request = new RegistrationRequest("Petarj12345213", "izmisljenemail", "Test", "Test");
       mockMvc.perform(post("/api/auth/register")
                       .contentType(MediaType.APPLICATION_JSON)
                       .content(mapper.writeValueAsString(request)))
               .andExpect(status().isBadRequest());

       assertThrows(InvalidEmailException.class, () -> {
           authService.register(request.username(), request.email(), request.password(), request.confirmPassword());
       });
   }

    @Test
    void authenticateUser_success_shouldReturn200() throws Exception {
       LoginRequest request = new LoginRequest("Petarj12345", "Test123#");

        mockMvc.perform(post("/api/auth/login")
               .contentType(MediaType.APPLICATION_JSON)
               .content(mapper.writeValueAsString(request)))
               .andExpect(status().isOk());
    }
    @Test
    void authenticateUser_failure_shouldReturn401() throws Exception {
        LoginRequest request = new LoginRequest("Petarj12345", "Test1234#");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    private void saveUser() {
        User user = User.builder()
                .username("Petarj12345")
                .email("izmisljenemail@gmail.com")
                .password(passwordEncoder.encode("Test123#"))
                .roles(Set.of(Role.USER))
                .build();
        if(userRepository.findByUsername("Petarj12345").isPresent()) {
            return;
        }
        userRepository.save(user);
    }
}
