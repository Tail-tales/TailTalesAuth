package com.tailtales.backend.auth.controller;

import com.tailtales.backend.auth.dto.AdminLoginRequestDto;
import com.tailtales.backend.auth.dto.AdminLoginResponseDto;
import com.tailtales.backend.auth.service.AuthService;
import com.tailtales.backend.auth.util.JwtUtil;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.NoSuchElementException;

@Log4j2
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Auth", description = "Authentication")
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    private static final String COOKIE_NAME = "refreshToken";

    // 중복되는 코드 메서드로 분리
    private void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie(COOKIE_NAME, refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setMaxAge((int) (jwtUtil.getRefreshTokenValiditySeconds() / 1000));
        refreshTokenCookie.setPath("/auth/refresh");
        response.addCookie(refreshTokenCookie);
    }

    // 관리자 아이디 중복 체크
    @GetMapping("/exists/id/{id}")
    public ResponseEntity<Boolean> checkDuplicateId(@PathVariable(name = "id") String id) {

        boolean isDuplicate = authService.isDuplicateId(id);
        return ResponseEntity.ok(isDuplicate);

    }

    // 관리자 이메일 중복 체크
    @GetMapping("/exists/email/{email}")
    public ResponseEntity<Boolean> checkDuplicateEmail(@PathVariable(name = "email") String email) {
        boolean isDuplicate = authService.isDuplicateEmail(email);
        return ResponseEntity.ok(isDuplicate);
    }

    // 관리자 로그인
    @PostMapping("/login")
    public ResponseEntity<AdminLoginResponseDto> login(@RequestBody AdminLoginRequestDto requestDto, HttpServletResponse response) {

        AdminLoginResponseDto responseDto = authService.login(requestDto.getId(), requestDto.getPassword());
        if (responseDto != null) {
            addRefreshTokenCookie(response, responseDto.getRefreshToken());
            return ResponseEntity.ok(AdminLoginResponseDto.builder()
                    .accessToken(responseDto.getAccessToken())
                    .tokenType(responseDto.getTokenType())
                    .expiresIn(responseDto.getExpiresIn())
                    .id(responseDto.getId())
                    .build());
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null); // Unauthorized (인증되지 않음)
        }

    }

    // 토큰 갱신 요청
    @PostMapping("/refresh")
    public ResponseEntity<AdminLoginResponseDto> refreshAccessToken(@CookieValue(value = COOKIE_NAME, required = false) String refreshToken, HttpServletResponse response) {

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null); // Refresh Token이 쿠키에 없음
        }

        AdminLoginResponseDto responseDto = authService.refreshAccessToken(refreshToken);
        if (responseDto != null) {
            addRefreshTokenCookie(response, responseDto.getRefreshToken());
            return ResponseEntity.ok(AdminLoginResponseDto.builder()
                    .accessToken(responseDto.getAccessToken())
                    .tokenType(responseDto.getTokenType())
                    .expiresIn(responseDto.getExpiresIn())
                    .id(responseDto.getId())
                    .build());
        } else {
            // Refresh Token이 유효하지 않음
            // 쿠키를 만료시켜 클라이언트에서 삭제하도록 유도
            Cookie expiredCookie = new Cookie(COOKIE_NAME, null);
            expiredCookie.setMaxAge(0);
            expiredCookie.setPath("/auth/refresh");
            response.addCookie(expiredCookie);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

    }

    // 관리자 비밀번호 찾기
    @PostMapping("/findPassword")
    public ResponseEntity<String> findPassword(@RequestParam String id) {

        try {
            authService.sendMail(id);
            return ResponseEntity.ok("새로운 비밀번호를 해당 관리자의 이메일로 발송했습니다.");
        } catch (NoSuchElementException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
        } catch (Exception e) {
            log.error(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("새로운 비밀번호 발송에 실패했습니다.");
        }

    }

}