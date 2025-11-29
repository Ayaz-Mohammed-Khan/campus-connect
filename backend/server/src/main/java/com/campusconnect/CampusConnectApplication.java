package com.campusconnect;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
// @EnableAsync  <-- REMOVED (Moved to AsyncConfig.java)
public class CampusConnectApplication {

    public static void main(String[] args) {
        SpringApplication.run(CampusConnectApplication.class, args);
    }

    @PostConstruct
    public void printDbInfo() {
        System.out.println("📌 USING DB: " + System.getProperty("spring.datasource.url"));
    }
}