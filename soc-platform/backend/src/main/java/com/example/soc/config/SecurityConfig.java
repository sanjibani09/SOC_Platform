
package com.example.soc.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${app.jwt-secret}")
    private String secret;

    @Value("${app.cors-origin}")
    private String origin;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    SecretKey key() {
        return Keys.hmacShaKeyFor(
                secret.getBytes(StandardCharsets.UTF_8)
        );
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration c = new CorsConfiguration();

        c.setAllowedOrigins(List.of(origin));

        c.setAllowedMethods(List.of(
                "GET", "POST", "PUT",
                "PATCH", "DELETE", "OPTIONS"
        ));

        c.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type"
        ));

        c.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", c);

        return source;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http)
            throws Exception {

        http
            .csrf(csrf -> csrf.disable())

            .cors(cors -> {})

            .sessionManagement(session ->
                session.sessionCreationPolicy(
                    SessionCreationPolicy.STATELESS
                )
            )

            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, exception) -> {
                    response.setStatus(
                        HttpServletResponse.SC_UNAUTHORIZED
                    );
                    response.setContentType("application/json");
                    response.getWriter().write(
                        "{\"error\":\"Authentication required or token invalid\"}"
                    );
                })
                .accessDeniedHandler((request, response, exception) -> {
                    response.setStatus(
                        HttpServletResponse.SC_FORBIDDEN
                    );
                    response.setContentType("application/json");
                    response.getWriter().write(
                        "{\"error\":\"Insufficient permissions\"}"
                    );
                })
            )

            .authorizeHttpRequests(auth -> auth

                .requestMatchers(
                    "/api/health",
                    "/api/auth/**",
                    "/actuator/health",
                    "/ws",
                    "/ws/**"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.OPTIONS,
                    "/**"
                ).permitAll()

                .anyRequest().authenticated()
            )

            .addFilterBefore(
                new JwtFilter(key()),
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }

    static class JwtFilter extends OncePerRequestFilter {
        @Override
protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getServletPath();

    return path.startsWith("/api/auth/")
            || request.getMethod().equalsIgnoreCase("OPTIONS");
}
        private final SecretKey key;

        JwtFilter(SecretKey key) {
            this.key = key;
        }

        @Override
        protected void doFilterInternal(
                HttpServletRequest request,
                HttpServletResponse response,
                FilterChain chain
        ) throws ServletException, IOException {

            String header = request.getHeader("Authorization");

            if (header != null && header.startsWith("Bearer ")) {

                String token = header.substring(7).trim();

                try {

                    var claims = Jwts.parser()
                            .verifyWith(key)
                            .build()
                            .parseSignedClaims(token)
                            .getPayload();

                    String email = claims.getSubject();
                    String role = claims.get("role", String.class);

                    if (email == null || email.isBlank()
                            || role == null
                            || !List.of("ADMIN", "ANALYST").contains(role)) {
                        throw new IllegalArgumentException(
                            "Invalid token claims"
                        );
                    }

                    var authentication =
                            new UsernamePasswordAuthenticationToken(
                                    email,
                                    null,
                                    List.of(
                                        new SimpleGrantedAuthority(
                                            "ROLE_" + role
                                        )
                                    )
                            );

                    org.springframework.security.core.context
                            .SecurityContextHolder
                            .getContext()
                            .setAuthentication(authentication);

                } catch (Exception ex) {

                    org.springframework.security.core.context
                            .SecurityContextHolder
                            .clearContext();

                    response.setStatus(
                            HttpServletResponse.SC_UNAUTHORIZED
                    );

                    response.setContentType("application/json");

                    response.getWriter().write(
                            "{\"error\":\"Invalid or expired JWT token\"}"
                    );

                    return;
                }
            }

            chain.doFilter(request, response);
        }
    }
}
