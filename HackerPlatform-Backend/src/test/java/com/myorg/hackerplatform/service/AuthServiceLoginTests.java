package com.myorg.hackerplatform.service;

import com.myorg.hackerplatform.jwt.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthServiceLoginTests {

    @Test
    void loginReturnsValidJwtForCorrectCredentials() {
        AuthenticationManager manager = authentication -> authentication;
        JwtUtil jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "secret", "lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=");
        ReflectionTestUtils.setField(jwtUtil, "expirationMs", 3600000);
        AuthService authService = new AuthService(manager, jwtUtil);

        String token = authService.login("alice", "password");

        assertEquals("alice", jwtUtil.parseClaims(token).getSubject());
    }
}
