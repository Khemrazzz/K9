package com.myorg.hackerplatform.service;

import com.myorg.hackerplatform.jwt.JwtUtil;
import com.myorg.hackerplatform.model.RefreshToken;
import com.myorg.hackerplatform.model.User;
import com.myorg.hackerplatform.repository.RefreshTokenRepository;
import com.myorg.hackerplatform.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthService {
    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshRepo;
    private final UserRepository userRepo;

    @Value("${jwt.refreshExpirationMs}")
    private int refreshExpirationMs;

    public AuthService(AuthenticationManager authManager, JwtUtil jwtUtil,
                       RefreshTokenRepository refreshRepo, UserRepository userRepo) {
        this.authManager = authManager;
        this.jwtUtil = jwtUtil;
        this.refreshRepo = refreshRepo;
        this.userRepo = userRepo;
    }

    public Map<String, String> login(String username, String password) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        String accessToken = jwtUtil.generateToken(auth.getName());
        String refreshToken = createRefreshToken(auth.getName());
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
        return tokens;
    }

    private String createRefreshToken(String username) {
        User user = userRepo.findByUsername(username).orElseThrow();
        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryDate(new Date(System.currentTimeMillis() + refreshExpirationMs));
        refreshRepo.save(token);
        return token.getToken();
    }

    public String refresh(String refreshToken) {
        RefreshToken token = refreshRepo.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        if (token.getExpiryDate().before(new Date())) {
            refreshRepo.delete(token);
            throw new RuntimeException("Expired refresh token");
        }
        return jwtUtil.generateToken(token.getUser().getUsername());
    }

    public void logout(String refreshToken) {
        refreshRepo.deleteByToken(refreshToken);
    }
}
