package com.auth.app.service;

import com.auth.app.DTO.UserEmailIdDTO;
import com.auth.app.exceptions.InvalidRoleException;
import com.auth.app.jwt.JwtService;
import com.auth.app.model.User;
import com.auth.app.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public void deleteUser(String token, String userId){
        if (isAdmin(token)){
            userRepository.deleteById(userId);
        } else throw new RuntimeException("Something went wrong");
    }
    private boolean isAdmin(String token){
        return !jwtService.isTokenExpired(token) && jwtService.extractRole(token).equals("MANAGER");
    }
}
