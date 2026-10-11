package com.myorg.hackerplatform.service;

import com.myorg.hackerplatform.jwt.JwtUtil;
import com.myorg.hackerplatform.model.User;
import com.myorg.hackerplatform.repository.RefreshTokenRepository;
import com.myorg.hackerplatform.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.util.ReflectionTestUtils;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthServiceLoginTests {

    @Test
    void loginReturnsValidJwtForCorrectCredentials() {
        AuthenticationManager manager = authentication -> authentication;
        JwtUtil jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "secret", "lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=");
        ReflectionTestUtils.setField(jwtUtil, "expirationMs", 3600000);
        ReflectionTestUtils.setField(jwtUtil, "refreshExpirationMs", 604800000);

        UserRepository userRepository = Mockito.mock(UserRepository.class);
        User user = new User();
        user.setId(1L);
        user.setUsername("alice");
        Mockito.when(userRepository.findByUsername("alice")).thenReturn(java.util.Optional.of(user));

        RefreshTokenRepository tokenRepo = Mockito.mock(RefreshTokenRepository.class);
        Mockito.when(tokenRepo.save(Mockito.any())).thenAnswer(inv -> inv.getArgument(0));
        RefreshTokenService refreshTokenService = new RefreshTokenService(tokenRepo);
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenDurationMs", 604800000L);

        AuthService authService = new AuthService(manager, jwtUtil, userRepository, refreshTokenService);

        var tokens = authService.login("alice", "password");

        assertEquals("alice", jwtUtil.parseClaims(tokens.accessToken()).getSubject());
        // refresh token should be generated and not empty
        org.junit.jupiter.api.Assertions.assertFalse(tokens.refreshToken().isEmpty());
    }
}
