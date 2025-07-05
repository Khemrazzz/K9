package com.myorg.hackerplatform.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.myorg.hackerplatform.jwt.JwtUtil;
import com.myorg.hackerplatform.model.RefreshToken;
import com.myorg.hackerplatform.model.User;
import com.myorg.hackerplatform.repository.UserRepository;
import com.myorg.hackerplatform.service.AuthService;
import com.myorg.hackerplatform.service.RefreshTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(AuthControllerRefreshTests.TestConfig.class)
@TestPropertySource(properties = {"jwt.secret=lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=", "JWT_SECRET=lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=", "jwt.expirationMs=3600000", "jwt.refreshExpirationMs=604800000"})
class AuthControllerRefreshTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtil jwtUtil;

    @MockBean
    private AuthService authService;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private RefreshTokenService refreshTokenService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void refreshRotatesTokenAndReturnsNewAccess() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setUsername("alice");
        RefreshToken existing = new RefreshToken();
        existing.setToken("old");
        existing.setUser(user);
        existing.setExpiryDate(Instant.now().plusSeconds(60));

        when(refreshTokenService.validateRefreshToken("old")).thenReturn(Optional.of(existing));

        RefreshToken newToken = new RefreshToken();
        newToken.setToken("new");
        newToken.setUser(user);
        newToken.setExpiryDate(Instant.now().plusSeconds(60));
        when(refreshTokenService.createRefreshToken(user)).thenReturn(newToken);

        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"old\"}"))
                .andExpect(status().isOk())
                .andReturn();

        verify(refreshTokenService).deleteRefreshToken("old");

        AuthTokens tokens = objectMapper.readValue(result.getResponse().getContentAsString(), AuthTokens.class);
        assertEquals("alice", jwtUtil.parseClaims(tokens.accessToken()).getSubject());
        assertEquals("new", tokens.refreshToken());
    }

    static class TestConfig {
        @Bean
        JwtUtil jwtUtil() {
            JwtUtil util = new JwtUtil();
            ReflectionTestUtils.setField(util, "secret", "lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=");
            ReflectionTestUtils.setField(util, "expirationMs", 3600000);
            ReflectionTestUtils.setField(util, "refreshExpirationMs", 604800000);
            return util;
        }
    }
}

