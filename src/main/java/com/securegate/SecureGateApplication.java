package com.securegate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SecureGateApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecureGateApplication.class, args);
    }
}
