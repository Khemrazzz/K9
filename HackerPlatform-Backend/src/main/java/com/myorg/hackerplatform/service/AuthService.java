package com.myorg.hackerplatform.service;

import com.myorg.hackerplatform.jwt.JwtUtil;
import com.myorg.hackerplatform.auth.AuthTokens;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    public AuthService(AuthenticationManager authManager, JwtUtil jwtUtil) {
        this.authManager = authManager;
        this.jwtUtil = jwtUtil;
    }

    public AuthTokens login(String username, String password) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        String access = jwtUtil.generateToken(auth.getName());
        String refresh = jwtUtil.generateRefreshToken(auth.getName());
        return new AuthTokens(access, refresh);
    }
}
