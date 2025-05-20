package com.tailtales.backend.auth.util;

import com.tailtales.backend.auth.service.CustomUserDetailsService;
import com.tailtales.backend.domain.member.entity.Member;
import com.tailtales.backend.domain.member.repository.MemberRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

@Log4j2
@Component
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final MemberRepository memberRepository;
    public static final String COOKIE_NAME = "refreshToken";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (request.getRequestURI().equals("/auth/admin/refresh") && request.getMethod().equals("POST")) {
            Optional<Cookie> refreshTokenCookie = Arrays.stream(request.getCookies() != null ? request.getCookies() : new Cookie[0])
                    .filter(cookie -> cookie.getName().equals(COOKIE_NAME))
                    .findFirst();

            if (refreshTokenCookie.isPresent()) {
                String refreshToken = refreshTokenCookie.get().getValue();

                if (jwtUtil.validateRefreshToken(refreshToken)) {
                    Optional<Member> memberOptional = memberRepository.findByRefreshToken(refreshToken);
                    if (memberOptional.isPresent()) {
                        Member member = memberOptional.get();
                        UserDetails userDetails = customUserDetailsService.loadUserByUsername(member.getId());
                        UsernamePasswordAuthenticationToken authenticationToken =
                                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                        log.info("RefreshToken 인증 성공 - 사용자 ID: {}", member.getId());
                    } else {
                        log.warn("유효한 Refresh Token이지만, DB에 해당 사용자 없음.");
                    }
                } else {
                    log.warn("유효하지 않은 Refresh Token");
                }
            } else {
                log.warn("Refresh Token 쿠키가 없음");
            }
        }

        filterChain.doFilter(request, response);
    }

}
