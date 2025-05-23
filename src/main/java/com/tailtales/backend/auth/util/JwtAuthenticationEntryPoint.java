package com.tailtales.backend.auth.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tailtales.backend.common.dto.ErrorDto;
import com.tailtales.backend.common.enumType.ErrorCode;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.SignatureException;

@Log4j2
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper; // JSON 변환을 위해 ObjectMapper 주입

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.warn("인증 실패 (AuthenticationException) 발생: {}", authException.getMessage());

        ErrorCode errorCode = ErrorCode.UNAUTHORIZED; // 기본값

        // AuthenticationException의 cause를 확인하여 JwtException 종류를 구분
        Throwable cause = authException.getCause();
        if (cause instanceof ExpiredJwtException) {
            errorCode = ErrorCode.ACCESS_TOKEN_EXPIRED;
        } else if (cause instanceof MalformedJwtException) {
            errorCode = ErrorCode.MALFORMED_ACCESS_TOKEN;
        } else if (cause instanceof SignatureException) { // 유효하지 않은 서명 (변조된 토큰)
            errorCode = ErrorCode.INVALID_ACCESS_TOKEN;
        }
        // 다른 JwtException 타입도 필요하다면 추가

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(errorCode.getStatus().value()); // HTTP 상태 코드 설정
        response.setCharacterEncoding("UTF-8"); // 한글 깨짐 방지

        ErrorDto errorDto = ErrorDto.builder()
                .code(errorCode.getCode())
                .message(errorCode.getMessage())
                .build();

        // ErrorDto를 JSON 문자열로 변환하여 응답 본문에 작성
        objectMapper.writeValue(response.getWriter(), errorDto);
    }
}
