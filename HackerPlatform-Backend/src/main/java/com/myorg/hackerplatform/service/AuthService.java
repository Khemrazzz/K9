package com.myorg.hackerplatform.service;

import com.myorg.hackerplatform.jwt.JwtUtil;
import com.myorg.hackerplatform.auth.AuthTokens;
import com.myorg.hackerplatform.model.User;
import com.myorg.hackerplatform.repository.UserRepository;
import com.myorg.hackerplatform.service.RefreshTokenService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;

    public AuthService(AuthenticationManager authManager, JwtUtil jwtUtil,
                       UserRepository userRepository,
                       RefreshTokenService refreshTokenService) {
        this.authManager = authManager;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.refreshTokenService = refreshTokenService;
    }

    public AuthTokens login(String username, String password) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        String access = jwtUtil.generateToken(auth.getName());
        User user = userRepository.findByUsername(auth.getName()).orElseThrow();
        String refresh = refreshTokenService.createRefreshToken(user).getToken();
        return new AuthTokens(access, refresh);
    }
}
