package com.myorg.hackerplatform.auth;

import com.myorg.hackerplatform.service.AuthService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody AuthRequest req) {
        return authService.login(req.getUsername(), req.getPassword());
    }

    @PostMapping("/refresh")
    public Map<String, String> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        String accessToken = authService.refresh(refreshToken);
        return Map.of("accessToken", accessToken);
    }

    @PostMapping("/logout")
    public void logout(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        authService.logout(refreshToken);
    }
}
