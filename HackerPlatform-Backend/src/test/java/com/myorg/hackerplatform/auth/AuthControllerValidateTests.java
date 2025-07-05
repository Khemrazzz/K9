package com.myorg.hackerplatform.auth;

import com.myorg.hackerplatform.jwt.JwtUtil;
import com.myorg.hackerplatform.model.User;
import com.myorg.hackerplatform.repository.UserRepository;
import com.myorg.hackerplatform.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(AuthControllerValidateTests.TestConfig.class)
@TestPropertySource(properties = {"jwt.secret=lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=", "JWT_SECRET=lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=", "jwt.expirationMs=3600000", "jwt.refreshExpirationMs=604800000"})
class AuthControllerValidateTests {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private com.myorg.hackerplatform.service.RefreshTokenService refreshTokenService;

    @Autowired
    private JwtUtil jwtUtil;

    @Test
    void validateValidTokenReturnsUserDetails() throws Exception {
        String token = jwtUtil.generateToken("alice");
        User user = new User();
        user.setId(1L);
        user.setUsername("alice");
        when(userRepository.findByUsername(eq("alice"))).thenReturn(Optional.of(user));

        mockMvc.perform(get("/api/auth/validate")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.id").value(1))
                .andExpect(jsonPath("$.user.username").value("alice"));
    }

    @Test
    void validateInvalidTokenReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/auth/validate")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bad"))
                .andExpect(status().isUnauthorized());
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

