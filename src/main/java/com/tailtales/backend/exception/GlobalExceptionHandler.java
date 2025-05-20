package com.tailtales.backend.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler({UnauthorizedException.class, NoSuchElementException.class}) // 두 예외를 동시에 처리
    public ResponseEntity<Map<String, Object>> handleUnauthorizedAndNotFoundException(RuntimeException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.UNAUTHORIZED.value());
        body.put("error", "Unauthorized");
        body.put("message", ex.getMessage());
        body.put("path", ""); // 요청 경로를 포함할 수 있습니다. (필요 시 HttpServletRequest request 매개변수 추가)
        return new ResponseEntity<>(body, HttpStatus.UNAUTHORIZED);
    }

    // JWT 관련 예외를 처리하는 핸들러도 추가하는 것이 좋습니다.
    // 예를 들어, io.jsonwebtoken.security.SignatureException, io.jsonwebtoken.ExpiredJwtException 등
    // JwtUtil.validateRefreshToken()에서 이런 예외들이 발생할 수 있습니다.
    @ExceptionHandler(io.jsonwebtoken.JwtException.class)
    public ResponseEntity<Map<String, Object>> handleJwtException(io.jsonwebtoken.JwtException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.UNAUTHORIZED.value());
        body.put("error", "Unauthorized");
        body.put("message", "유효하지 않거나 변조된 토큰입니다: " + ex.getMessage());
        body.put("path", "");
        return new ResponseEntity<>(body, HttpStatus.UNAUTHORIZED);
    }


    // catch-all handler for other unexpected runtime exceptions
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        body.put("error", "Internal Server Error");
        body.put("message", "서버 내부 오류가 발생했습니다: " + ex.getMessage());
        body.put("path", "");
        // 개발/테스트 환경에서만 스택 트레이스 포함
        // body.put("trace", ex.getStackTrace());
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
