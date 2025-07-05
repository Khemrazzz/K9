package com.myorg.hackerplatform.auth;

import com.myorg.hackerplatform.jwt.JwtUtil;
import com.myorg.hackerplatform.service.AuthService;
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

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(AuthControllerLoginTests.TestConfig.class)
@TestPropertySource(properties = {"jwt.secret=lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=", "JWT_SECRET=lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=", "jwt.expirationMs=3600000"})
class AuthControllerLoginTests {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @Test
    void loginValidUserReturns200() throws Exception {
        when(authService.login(eq("alice"), eq("password"))).thenReturn("token");

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"password\"}"))
                .andExpect(status().isOk())
                .andExpect(content().string("token"));
    }

    static class TestConfig {
        @Bean
        JwtUtil jwtUtil() {
            JwtUtil util = new JwtUtil();
            ReflectionTestUtils.setField(util, "secret", "lw8Jk7ZQHtN4+ov2X3KqFv8JrW4dKC5gG5tf1x8b1Qs=");
            ReflectionTestUtils.setField(util, "expirationMs", 3600000);
            return util;
        }
    }
}
