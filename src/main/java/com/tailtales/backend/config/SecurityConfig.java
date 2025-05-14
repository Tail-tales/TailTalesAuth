package com.tailtales.backend.config;

import com.tailtales.backend.auth.service.CustomOAuth2UserService;
import com.tailtales.backend.auth.service.CustomUserDetailsService;
import com.tailtales.backend.auth.util.JwtFilter;
import com.tailtales.backend.auth.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String COOKIE_NAME = "refreshToken";

    private final JwtUtil jwtUtil;
    private final JwtFilter jwtFilter;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder);
    }

    private void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie(COOKIE_NAME, refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setMaxAge((int) (jwtUtil.getRefreshTokenValiditySeconds() / 1000));
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setSecure(false);
        response.addCookie(refreshTokenCookie);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CustomOAuth2UserService customOAuth2UserService) throws Exception {
        http
                .csrf((csrf) -> csrf.disable()) // CSRF 비활성화
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                        .requestMatchers(POST, "/api/members").permitAll() // 회원가입
                        .requestMatchers("/auth/login").permitAll() // 로그인
                        .requestMatchers(GET, "/auth/exists/id/**").permitAll() // 아이디 중복체크
                        .requestMatchers(GET, "/auth/exists/email/**").permitAll() // 이메일 중복체크
                        .requestMatchers(POST, "/auth/findPassword/**").permitAll() // 비밀번호 찾기
                        .requestMatchers("/api/members/**").hasRole("ADMIN")
                        .anyRequest().authenticated() // 나머지 요청은 인증 필요
                )
                .sessionManagement((sessionManagement) ->
                        sessionManagement.sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.STATELESS) // 세션 사용 안 함
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2Login(oauth2 -> oauth2.userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        .successHandler((request, response, authentication) -> {
                            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
                            String accessToken = oAuth2User.getAttribute("accessToken");
                            String refreshToken = oAuth2User.getAttribute("refreshToken");
                            String nickname = oAuth2User.getAttribute("nickname");
                            String email = oAuth2User.getAttribute("email");

                            // Access Token 쿠키에 저장
                            Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
                            accessTokenCookie.setHttpOnly(true);
                            accessTokenCookie.setPath("/");
                            accessTokenCookie.setSecure(false);
                            response.addCookie(accessTokenCookie);

                            // Refresh Token 쿠키에 저장
                            addRefreshTokenCookie(response, refreshToken);

                            // 닉네임 쿠키에 저장 (선택 사항)
                            Cookie nicknameCookie = new Cookie("nickname", nickname);
                            nicknameCookie.setPath("/");
                            response.addCookie(nicknameCookie);

                            // 이메일 쿠키에 저장 (선택 사항)
                            Cookie emailCookie = new Cookie("email", email);
                            emailCookie.setPath("/");
                            response.addCookie(emailCookie);

                            // 리다이렉트 (프론트 페이지 생성 시 변경 필수!!!!!!)
                            response.sendRedirect("http://localhost:5173");
                        }))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable());
        return http.build();
    }
}