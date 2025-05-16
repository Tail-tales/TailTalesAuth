package com.tailtales.backend.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
public class EnvConfig {

    @Value("${jwt.secret-key}")
    private String jwtSecretKey;

    @Value("${jwt.refresh-secret-key}")
    private String jwtRefreshSecretKey;

    @Value("${jwt.access-token-validity-seconds}")
    private long accessTokenValiditySeconds;

    @Value("${jwt.refresh-token-validity-seconds}")
    private long refreshTokenValiditySeconds;

}
