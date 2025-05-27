package com.tailtales.backend.auth.controller;

import com.tailtales.backend.auth.dto.AdminLoginRequestDto;
import com.tailtales.backend.auth.dto.AdminLoginResponseDto;
import com.tailtales.backend.auth.service.AuthService;
import com.tailtales.backend.auth.util.JwtUtil;
import com.tailtales.backend.common.enumType.ErrorCode;
import com.tailtales.backend.common.exception.CustomException;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import static com.tailtales.backend.common.constants.ApiConstants.*;

@Log4j2
@RestController
@RequestMapping(ADMIN_AUTH_BASE_URL)
@RequiredArgsConstructor
@Tag(name = "Auth", description = "Authentication")
public class AdminAuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    private static final String COOKIE_NAME = "refreshToken";

    // 관리자 토큰 인증
    @GetMapping("/verify")
    public ResponseEntity<String> verifyToken() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("/auth/verify 엔드포인트에 인증되지 않은 요청이 도달했습니다.");
            throw new CustomException(ErrorCode.UNAUTHORIZED);
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

        addRefreshTokenCookie(response, responseDto.getRefreshToken());
        return ResponseEntity.ok(AdminLoginResponseDto.builder()
                .accessToken(responseDto.getAccessToken())
                .tokenType(responseDto.getTokenType())
                .expiresIn(responseDto.getExpiresIn())
                .id(responseDto.getId())
                .build());

    }

    // 관리자 로그아웃
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authorizationHeader,
                                       HttpServletResponse response) {

        String token = jwtUtil.extractTokenFromHeader(authorizationHeader);
        if (token == null) {
            throw new CustomException(ErrorCode.EMPTY_ACCESS_TOKEN);
        }

        Claims claims;
        try {
            claims = jwtUtil.getClaimsFromToken(token);

        } catch (io.jsonwebtoken.JwtException e) {

            throw new CustomException(ErrorCode.INVALID_ACCESS_TOKEN);
        }

        String memberId = claims.getSubject();
        authService.logout(memberId);

        // refreshToken 쿠키 삭제
        Cookie cookie = new Cookie(COOKIE_NAME, null);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0); // 즉시 만료
        cookie.setPath("/");
        response.addCookie(cookie);

        return ResponseEntity.ok().build();

    }

    // 관리자 토큰 갱신 요청
    @PostMapping("/refresh")
    public ResponseEntity<AdminLoginResponseDto> refreshAdminAccessToken(@CookieValue(value = COOKIE_NAME, required = false) String refreshToken, HttpServletResponse response) {

        if (refreshToken == null) {
            throw new CustomException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        AdminLoginResponseDto responseDto = authService.refreshAdminAccessToken(refreshToken);

        addRefreshTokenCookie(response, responseDto.getRefreshToken());
        return ResponseEntity.ok(AdminLoginResponseDto.builder()
                .accessToken(responseDto.getAccessToken())
                .tokenType(responseDto.getTokenType())
                .expiresIn(responseDto.getExpiresIn())
                .id(responseDto.getId())
                .build());

    }

    // 관리자 비밀번호 찾기
    @PostMapping("/findPassword")
    public ResponseEntity<String> findPassword(@RequestParam(name = "id") String id) {

        authService.sendMail(id);
        return ResponseEntity.ok("새로운 비밀번호를 해당 관리자의 이메일로 발송했습니다.");

    }

}