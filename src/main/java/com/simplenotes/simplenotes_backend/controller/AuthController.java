package com.simplenotes.simplenotes_backend.controller;

import com.simplenotes.simplenotes_backend.dto.UserDTO;
import com.simplenotes.simplenotes_backend.model.User;
import com.simplenotes.simplenotes_backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserDTO> register(@RequestBody User user) {
        User registeredUser = authService.registerUser(user.getUsername(), user.getEmail(), user.getPassword());
        UserDTO userDTO = new UserDTO(registeredUser.getUsername(), registeredUser.getEmail());
        return ResponseEntity.ok(userDTO);
    }


    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody User user) {
        String token = authService.authenticate(user.getEmail(), user.getPassword());

        Map<String, String> response = new HashMap<>();
        response.put("token", token);

        return ResponseEntity.ok(response);
    }

}
