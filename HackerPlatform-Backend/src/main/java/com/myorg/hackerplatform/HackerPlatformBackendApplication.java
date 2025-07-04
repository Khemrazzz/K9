package com.myorg.hackerplatform;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.myorg.hackerplatform.HackerPlatform")
public class HackerPlatformBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(HackerPlatformBackendApplication.class, args);
	}

}
