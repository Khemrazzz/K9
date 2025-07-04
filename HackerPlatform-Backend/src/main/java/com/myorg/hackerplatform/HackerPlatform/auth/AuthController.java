package com.myorg.hackerplatform.auth;

import com.myorg.hackerplatform.service.AuthService;
import com.myorg.hackerplatform.jwt.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;
    private final JwtUtil jwtUtil;

    public AuthController(AuthService authService, JwtUtil jwtUtil) {
        this.authService = authService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public String login(@RequestBody AuthRequest req) {
        return authService.login(req.getUsername(), req.getPassword());
    }

    @GetMapping("/verify")
    public ResponseEntity<?> verify(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String token = authorization.substring(7);
        try {
            Claims claims = jwtUtil.parseClaims(token);
            return ResponseEntity.ok(
                    java.util.Map.of("user", java.util.Map.of("username", claims.getSubject()))
            );
        } catch (JwtException | IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
