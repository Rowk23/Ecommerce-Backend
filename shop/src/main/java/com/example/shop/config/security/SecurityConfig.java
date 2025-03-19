package com.example.shop.config.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Value("${keySetUri}")
    private String keySetUri;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .oauth2ResourceServer(c -> c.jwt(
                    j -> j.jwkSetUri(keySetUri)
                )
            )
            .authorizeHttpRequests(r ->
                r.anyRequest().permitAll()
            )
            .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

}