package com.myorg.hackerplatform.auth;

import com.myorg.hackerplatform.service.AuthService;
import com.myorg.hackerplatform.jwt.JwtUtil;
import com.myorg.hackerplatform.repository.UserRepository;
import com.myorg.hackerplatform.model.User;
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
    private final UserRepository userRepository;

    public AuthController(AuthService authService, JwtUtil jwtUtil, UserRepository userRepository) {
        this.authService = authService;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    @PostMapping("/login")
    public String login(@RequestBody AuthRequest req) {
        return authService.login(req.getUsername(), req.getPassword());
    }

    // Endpoint used by the frontend verifySession() helper to check the
    // currently stored JWT and retrieve the associated user information.
    @GetMapping("/verify")
    public ResponseEntity<?> verifySession(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
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

    @GetMapping("/user")
    public ResponseEntity<?> getUser(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String token = authorization.substring(7);
        try {
            Claims claims = jwtUtil.parseClaims(token);
            String username = claims.getSubject();
            return userRepository.findByUsername(username)
                    .map(user -> ResponseEntity.ok(
                            java.util.Map.of(
                                    "user",
                                    java.util.Map.of(
                                            "id", user.getId(),
                                            "username", user.getUsername()
                                    )
                            )
                    ))
                    .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
        } catch (JwtException | IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
