package com.myorg.hackerplatform;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = "JWT_SECRET=dummy")
class HackerPlatformBackendApplicationTests {

	@Test
	void contextLoads() {
	}

}
