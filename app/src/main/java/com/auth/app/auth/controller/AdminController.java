package com.auth.app.auth.controller;


import com.auth.app.auth.DTO.RegistrationRequest;
import com.auth.app.auth.exceptions.*;
import com.auth.app.auth.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public void registerAdmin(@RequestBody RegistrationRequest request) throws PasswordMismatchException, InvalidPasswordException, UsernameExistsException, EmailExistsException, InvalidEmailException {
        adminService.register(request.username(), request.email(), request.password(), request.confirmPassword());
    }
    @PutMapping("/promote")
    @ResponseStatus(HttpStatus.OK)
    public void promoteUserToAdmin(@RequestParam String usernameOrEmail){
        adminService.promoteUserToAdmin(usernameOrEmail);
    }
    @PutMapping("/demote")
    @ResponseStatus(HttpStatus.OK)
    public void demoteToUserFromAdmin(@RequestParam String usernameOrEmail){
        adminService.demoteUserFromAdmin(usernameOrEmail);
    }
    @PutMapping("/ban")
    @ResponseStatus(HttpStatus.OK)
    public void banUser(@RequestParam String usernameOrEmail){
        adminService.banUser(usernameOrEmail);
    }
    @PutMapping("/unban")
    @ResponseStatus(HttpStatus.OK)
    public void unbanUser(@RequestParam String usernameOrEmail){
        adminService.unbanUser(usernameOrEmail);
    }
}
