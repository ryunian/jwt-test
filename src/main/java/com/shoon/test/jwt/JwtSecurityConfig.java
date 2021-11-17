package com.shoon.test.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private final TokenProvider tokenProvider;

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        JwtFilter filter = new JwtFilter(tokenProvider);
        // JwtFiler 를 security 로직에 적용
        builder.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }
}
