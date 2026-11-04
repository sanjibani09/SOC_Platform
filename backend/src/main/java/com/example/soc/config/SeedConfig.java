package com.example.soc.config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
@Configuration
public class SeedConfig {
 @Bean CommandLineRunner seed(JdbcTemplate db, PasswordEncoder encoder,@Value("${SOC_ADMIN_EMAIL:admin@soc.local}") String email,@Value("${SOC_ADMIN_PASSWORD:ChangeMe123!}") String password){return args->{Integer n=db.queryForObject("SELECT count(*) FROM users",Integer.class);if(n==0)db.update("INSERT INTO users(email,password_hash,role) VALUES (?,?, 'ADMIN')",email,encoder.encode(password));};}
}
