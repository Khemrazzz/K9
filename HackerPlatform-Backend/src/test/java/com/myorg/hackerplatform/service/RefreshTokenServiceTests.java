package com.myorg.hackerplatform.service;

import com.myorg.hackerplatform.model.RefreshToken;
import com.myorg.hackerplatform.model.User;
import com.myorg.hackerplatform.repository.RefreshTokenRepository;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RefreshTokenServiceTests {

    @Test
    void createAndValidateToken() {
        RefreshTokenRepository repo = mock(RefreshTokenRepository.class);
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        RefreshTokenService service = new RefreshTokenService(repo);
        ReflectionTestUtils.setField(service, "refreshTokenDurationMs", 1000L);

        User user = new User();
        user.setId(1L);
        user.setUsername("alice");

        RefreshToken token = service.createRefreshToken(user);
        when(repo.findByToken(token.getToken())).thenReturn(Optional.of(token));

        Optional<RefreshToken> validated = service.validateRefreshToken(token.getToken());
        assertTrue(validated.isPresent());
        assertEquals(user, validated.get().getUser());
    }

    @Test
    void expiredTokenFailsValidation() {
        RefreshTokenRepository repo = mock(RefreshTokenRepository.class);
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        RefreshTokenService service = new RefreshTokenService(repo);
        ReflectionTestUtils.setField(service, "refreshTokenDurationMs", 0L);

        User user = new User();
        user.setId(1L);
        user.setUsername("alice");

        RefreshToken token = service.createRefreshToken(user);
        when(repo.findByToken(token.getToken())).thenReturn(Optional.of(token));

        Optional<RefreshToken> validated = service.validateRefreshToken(token.getToken());
        assertFalse(validated.isPresent());
    }
}

