package com.tailtales.backend.auth.util;

import com.tailtales.backend.config.EnvConfig;
import com.tailtales.backend.domain.member.entity.MemberRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Log4j2
@Getter
@Component
public class JwtUtil {

    private final Key accessKey;
    private final long accessTokenValiditySeconds;

    private final Key refreshKey;
    private final long refreshTokenValiditySeconds;

    public JwtUtil(EnvConfig envConfig) {

        String secretKey = envConfig.getJwtSecretKey();
        String refreshSecretKey = envConfig.getJwtRefreshSecretKey();
        long accessTokenValiditySeconds = envConfig.getAccessTokenValiditySeconds();
        long refreshTokenValiditySeconds = envConfig.getRefreshTokenValiditySeconds();

        byte[] accessKeyBytes = Decoders.BASE64.decode(secretKey);
        this.accessKey = Keys.hmacShaKeyFor(accessKeyBytes);
        this.accessTokenValiditySeconds = accessTokenValiditySeconds * 1000;

        byte[] refreshKeyBytes = Decoders.BASE64.decode(refreshSecretKey);
        this.refreshKey = Keys.hmacShaKeyFor(refreshKeyBytes);
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds * 1000;

    }

    // JWT 토큰 생성 메서드
    public String generateAccessToken(String subject, Map<String, Object> claims, MemberRole memberRole) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenValiditySeconds);

        Map<String, Object> allClaims = new HashMap<>(claims != null ? claims : Map.of());
        allClaims.put("roles", List.of(memberRole.name()));

        return Jwts.builder()
                .setClaims(allClaims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(accessKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // Refresh JWT 토큰 생성 메서드
    public String generateRefreshToken() {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshTokenValiditySeconds);

        return Jwts.builder()
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(refreshKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // JWT 토큰에서 Subject 추출 메서드
    public String getSubjectFromAccessToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(accessKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // JWT 토큰 유효성 검증 메서드
    public boolean validateAccessToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(accessKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            // 토큰이 유효하지 않은 경우 (만료, 변조 등)
            log.error("Invalid Access Token", e);
            return false;
        }
    }

    public Claims getClaimsFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(accessKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            log.error("Failed to get claims from token", e);
            return null;
        }
    }

    // Authorization 헤더에서 토큰 추출
    public String extractTokenFromHeader(String authorizationHeader) {
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }

    // Refresh JWT 토큰 유효성 검증 메서드
    public boolean validateRefreshToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(refreshKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            log.error("Invalid Refresh Token", e);
            return false;
        }
    }

    // Access JWT 토큰 만료 시간 추출 메서드
    public long getExpirationTimeFromAccessToken(String token) {
        Claims claims = getClaimsFromToken(token);
        if (claims != null) {
            Date expiration = claims.getExpiration();
            if (expiration != null) {
                return expiration.getTime();
            } else {
                log.warn("Access token does not contain expiration time.");
                return 0;
            }
        } else {
            log.error("Failed to parse access token.");
            return 0;
        }
    }

    // Refresh JWT 토큰 만료 시간 추출 메서드
    public long getExpirationTimeFromRefreshToken(String token) {
        Date expiration = Jwts.parserBuilder()
                .setSigningKey(refreshKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expiration.getTime();
    }



}
