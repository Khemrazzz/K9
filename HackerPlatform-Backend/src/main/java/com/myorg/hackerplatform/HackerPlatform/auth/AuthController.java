package com.myorg.hackerplatform.auth;

import com.myorg.hackerplatform.service.AuthService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public String login(@RequestBody AuthRequest req) {
        return authService.login(req.getUsername(), req.getPassword());
    }
}
