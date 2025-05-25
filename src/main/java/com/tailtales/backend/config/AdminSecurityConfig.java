package com.tailtales.backend.config;

import com.tailtales.backend.auth.service.CustomUserDetailsService;
import com.tailtales.backend.auth.util.JwtAuthenticationEntryPoint;
import com.tailtales.backend.auth.util.JwtFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;
import static com.tailtales.backend.common.constants.ApiConstants.*;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@Order(1)
@RequiredArgsConstructor
public class AdminSecurityConfig {

    private final JwtFilter jwtFilter;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        final String[] POST_WHITE_LIST = {
                ADMIN_REGISTER,
                ADMIN_LOGIN,
                ADMIN_TOKEN_REFRESH,
                ADMIN_FIND_PASSWORD + "/**"
        };

        final String[] GET_WHITE_LIST = {
                ADMIN_CHECK_ID + "/**",
                ADMIN_CHECK_EMAIL + "/**"
        };

        http
                .csrf((csrf) -> csrf.disable()) // CSRF 비활성화
                .securityMatcher(ADMIN_AUTH_BASE_URL +"/**", ADMIN_BASE_URL + "/**")
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                        .requestMatchers(POST, POST_WHITE_LIST).permitAll()
                        .requestMatchers(GET, GET_WHITE_LIST).permitAll()
                        .requestMatchers(ERROR_URL + "/**").permitAll()
                        .requestMatchers(GET, ADMIN_VERIFY_TOKEN).authenticated()
                        .requestMatchers(ADMIN_BASE_URL + "/**").hasRole("ADMIN")
                        .anyRequest().authenticated() // 나머지 요청은 인증 필요
                )
                .sessionManagement((sessionManagement) ->
                        sessionManagement.sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.STATELESS) // 세션 사용 안 함
                )
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling
                                .authenticationEntryPoint(jwtAuthenticationEntryPoint) // 이 부분 추가
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable());
        return http.build();
    }
}