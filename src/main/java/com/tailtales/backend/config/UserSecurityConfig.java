package com.tailtales.backend.config;

import com.tailtales.backend.auth.service.CustomOAuth2UserService;
import com.tailtales.backend.auth.util.JwtFilter;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;

@Configuration
@Order(2)
@RequiredArgsConstructor
public class UserSecurityConfig {

    private final JwtFilter jwtFilter;
    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public SecurityFilterChain userSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .securityMatcher("/api/user/**", "/oauth2/**", "/login/oauth2/code/**")
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(CorsUtils::isPreFlightRequest).permitAll();
                    auth.requestMatchers("/oauth2/**", "/login/oauth2/code/**").permitAll();
                    auth.anyRequest().authenticated();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        .successHandler((request, response, authentication) -> {
                            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
                            String accessToken = oAuth2User.getAttribute("accessToken");
                            String refreshToken = oAuth2User.getAttribute("refreshToken");
                            String nickname = oAuth2User.getAttribute("nickname");
                            String email = oAuth2User.getAttribute("email");

                            Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
                            accessTokenCookie.setHttpOnly(true);
                            accessTokenCookie.setPath("/");
                            response.addCookie(accessTokenCookie);

                            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
                            refreshTokenCookie.setHttpOnly(true);
                            refreshTokenCookie.setPath("/");
                            response.addCookie(refreshTokenCookie);

                            Cookie nicknameCookie = new Cookie("nickname", nickname);
                            nicknameCookie.setPath("/");
                            response.addCookie(nicknameCookie);

                            Cookie emailCookie = new Cookie("email", email);
                            emailCookie.setPath("/");
                            response.addCookie(emailCookie);

                            response.sendRedirect("http://localhost:5173");
                        }))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable());

        return http.build();
    }
}

