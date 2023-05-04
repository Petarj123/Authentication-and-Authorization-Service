package com.auth.app.controller;

import com.auth.app.DTO.RegistrationRequest;
import com.auth.app.DTO.UserEmailIdDTO;
import com.auth.app.service.AdminService;
import com.auth.app.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AuthenticationService authenticationService;
    private final AdminService adminService;
    @DeleteMapping("/delete/{id}")
    @ResponseStatus(HttpStatus.OK)
    public void deleteUser(@RequestHeader("Authorization") String header, @PathVariable("id") String userId){
        String token = header.substring(7);
        adminService.deleteUser(token, userId);
    }
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public void registerAdmin(@RequestBody RegistrationRequest request, @RequestHeader("Authorization") String header){
        String token = header.substring(7);
        authenticationService.registerAdmin(request, token);
    }
    @GetMapping("/users")
    @ResponseStatus(HttpStatus.OK)
    public List<UserEmailIdDTO> getUsers(@RequestHeader("Authorization") String header){
        String token = header.substring(7);
        return adminService.getUsers(token);
    }
}
