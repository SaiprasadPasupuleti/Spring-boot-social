package com.pgacapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.context.annotation.PropertySource;

@SpringBootApplication
(exclude = { SecurityAutoConfiguration.class })
public class SpringBootSocialApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootSocialApplication.class, args);
	}
}
