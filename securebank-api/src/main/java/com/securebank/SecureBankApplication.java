package com.securebank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = "com.securebank")
@EnableJpaRepositories(basePackages = "com.securebank.repository")
@EntityScan(basePackages = "com.securebank.domain")
public class SecureBankApplication {

    public static void main(String[] args) {
        System.out.println("==========================================================");
        System.out.println("  SecureBank - Educational Vulnerable Banking Platform");
        System.out.println("  WARNING: Contains INTENTIONAL security vulnerabilities");
        System.out.println("  For educational purposes only - DO NOT use in production");
        System.out.println("==========================================================");
        SpringApplication.run(SecureBankApplication.class, args);
    }
}
