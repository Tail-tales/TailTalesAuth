package com.tailtales.backend.auth.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tailtales.backend.auth.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {

        String method = request.getMethod();

        if (method.equals("OPTIONS")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // 토큰이 없거나 "Bearer "로 시작하지 않는 경우 (401이 아닌 경우)
        if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // 다음 필터로 넘기거나, SecurityContextHolder에 인증 없음
            return; // 여기서 return하여 다음 필터 체인을 진행하지 않습니다.
        }

        final String jwtToken = authHeader.substring(7); // "Bearer " 제외

        try {
            if (jwtUtil.validateAccessToken(jwtToken)) {
                final String id = jwtUtil.getSubjectFromAccessToken(jwtToken);

                if (id != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(id);
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            } else {
                // validateAccessToken이 false를 반환했을 때
                throw new BadCredentialsException("Invalid or expired JWT token");
            }
        } catch (AuthenticationException e) { // BadCredentialsException은 AuthenticationException의 하위 클래스
            // 인증 관련 예외 발생 시, 직접 401 응답을 보냅니다.
            jwtAuthenticationEntryPoint.commence(request, response, e);
            return; // 여기서 필터 체인 진행을 중단합니다.
        } catch (Exception e) {
            // 그 외 예상치 못한 다른 모든 예외
            // 500 Internal Server Error를 반환하거나, 적절한 에러 메시지를 보냅니다.
            // 여기서는 임시로 500을 보내도록 처리합니다. 실제 프로덕션에서는 더 구체적인 처리가 필요합니다.
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("timestamp", new java.util.Date());
            errorDetails.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
            errorDetails.put("error", "Internal Server Error");
            errorDetails.put("message", "Unhandled exception in JWT filter: " + e.getMessage());
            errorDetails.put("path", request.getRequestURI());
            new ObjectMapper().writeValue(response.getWriter(), errorDetails);
            return; // 여기서 필터 체인 진행을 중단합니다.
        }

        // 토큰이 유효하여 인증이 성공했거나, 토큰이 아예 없는 경우에만 다음 필터로 진행
        filterChain.doFilter(request, response);
    }

}
