package com.tailtales.backend.auth.controller;

import com.tailtales.backend.auth.dto.AdminLoginRequestDto;
import com.tailtales.backend.auth.dto.AdminLoginResponseDto;
import com.tailtales.backend.auth.dto.UserLoginResponseDto;
import com.tailtales.backend.auth.service.AuthService;
import com.tailtales.backend.auth.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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

    // 관리자 토큰 인증
    @GetMapping("/verify")
    public ResponseEntity<String> verifyToken() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("/auth/verify 엔드포인트에 인증되지 않은 요청이 도달했습니다.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("인증된 사용자 정보가 없습니다.");
        }

        String memberId = authentication.getName();

        return ResponseEntity.ok(memberId);

    }

    // 중복되는 코드 메서드로 분리
    private void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie(COOKIE_NAME, refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setMaxAge((int) (jwtUtil.getRefreshTokenValiditySeconds() / 1000));
        refreshTokenCookie.setPath("/");
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

    // 관리자 로그아웃
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authorizationHeader,
                                       HttpServletResponse response) {

        String token = jwtUtil.extractTokenFromHeader(authorizationHeader);
        if (token != null) {
            Claims claims = jwtUtil.getClaimsFromToken(token);
            if (claims != null) {
                String memberId = claims.getSubject();
                try {
                    authService.logout(memberId);

                    // refreshToken 쿠키 삭제
                    Cookie cookie = new Cookie(COOKIE_NAME, null);
                    cookie.setHttpOnly(true);
                    cookie.setMaxAge(0); // 즉시 만료
                    cookie.setPath("/");
                    response.addCookie(cookie);

                    return ResponseEntity.ok().build();
                } catch (NoSuchElementException e) {
                    return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
                }
            }
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }

    // 관리자 토큰 갱신 요청
    @PostMapping("/admin/refresh")
    public ResponseEntity<AdminLoginResponseDto> refreshAdminAccessToken(@CookieValue(value = COOKIE_NAME, required = false) String refreshToken, HttpServletResponse response) {

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null); // Refresh Token이 쿠키에 없음
        }

        AdminLoginResponseDto responseDto = authService.refreshAdminAccessToken(refreshToken);
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
            expiredCookie.setPath("/");
            response.addCookie(expiredCookie);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

    }

    // 사용자 토큰 갱신 요청
    @PostMapping("/user/refresh")
    public ResponseEntity<UserLoginResponseDto> refreshUserAccessToken(@CookieValue(value = COOKIE_NAME, required = false) String refreshToken, HttpServletResponse response) {

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null); // Refresh Token이 쿠키에 없음
        }

        UserLoginResponseDto responseDto = authService.refreshUserAccessToken(refreshToken);
        if (responseDto != null) {
            addRefreshTokenCookie(response, responseDto.getRefreshToken());
            return ResponseEntity.ok(UserLoginResponseDto.builder()
                    .accessToken(responseDto.getAccessToken())
                    .tokenType(responseDto.getTokenType())
                    .expiresIn(responseDto.getExpiresIn())
                    .name(responseDto.getName())
                    .email(responseDto.getEmail())
                    .build());
        } else {
            // Refresh Token이 유효하지 않음
            // 쿠키를 만료시켜 클라이언트에서 삭제하도록 유도
            Cookie expiredCookie = new Cookie(COOKIE_NAME, null);
            expiredCookie.setMaxAge(0);
            expiredCookie.setPath("/");
            response.addCookie(expiredCookie);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

    }

    // 관리자 비밀번호 찾기
    @PostMapping("/findPassword")
    public ResponseEntity<String> findPassword(@RequestParam(name = "id") String id) {

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