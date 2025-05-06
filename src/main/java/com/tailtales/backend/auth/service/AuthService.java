package com.tailtales.backend.auth.service;

import com.tailtales.backend.auth.dto.AdminInsertRequestDto;
import com.tailtales.backend.auth.dto.AdminLoginResponseDto;
import com.tailtales.backend.auth.util.JwtUtil;
import com.tailtales.backend.domain.member.entity.Member;
import com.tailtales.backend.domain.member.entity.MemberRole;
import com.tailtales.backend.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final MemberRepository memberRepository;

    public void insertAdmin(AdminInsertRequestDto dto) {

        if (memberRepository.existsById(dto.getId())) {

            throw new IllegalArgumentException("이미 사용 중인 아이디입니다.");

        }

        if (memberRepository.existsByEmail(dto.getEmail())) {

            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");

        }

        Member member = Member.builder()
                .name(dto.getName())
                .id(dto.getId())
                .password(bCryptPasswordEncoder.encode(dto.getPassword()))
                .contact(dto.getContact())
                .email(dto.getEmail())
                .role(MemberRole.ROLE_ADMIN)
                .isDeleted(false)
                .build();

        memberRepository.save(member);

    }

    public boolean isDuplicateId(String id) {
        return memberRepository.existsById(id);
    }

    public boolean isDuplicateEmail(String email) { return memberRepository.existsByEmail(email); }

    public AdminLoginResponseDto login(String id, String password) {

        // 사용자 인증 (AuthenticationManager 사용)
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(id, password)
        );

        // 인증 성공 시 JWT 토큰 생성
        if (authentication.isAuthenticated()) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(id);
            Member member = memberRepository.findById(id)
                    .orElseThrow(() -> new NoSuchElementException("해당 아이디의 회원을 찾을 수 없습니다."));
            String accessToken = jwtUtil.generateAccessToken(userDetails.getUsername(), Map.of("roles", List.of(member.getRole().name())), member.getRole());
            String refreshToken = jwtUtil.generateRefreshToken();

            long accessTokenExpiresIn = jwtUtil.getExpirationTimeFromAccessToken(accessToken);
            long refreshTokenExpiresIn = jwtUtil.getExpirationTimeFromRefreshToken(refreshToken);

            // refresh token DB에 저장
            Member updatedAdmin = member.toBuilder()
                    .refreshToken(refreshToken)
                    .build();

            memberRepository.save(updatedAdmin);

            return AdminLoginResponseDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .expiresIn(accessTokenExpiresIn / 1000) // 초 단위로 변환
                    .refreshExpiresIn(refreshTokenExpiresIn / 1000) // 초 단위로 변환
                    .id(id)
                    .build();
        }

        return null; // 인증 실패
    }

    public AdminLoginResponseDto refreshAccessToken(String refreshToken) {

        // 1. refreshToken 유효성 검증
        if (!jwtUtil.validateRefreshToken(refreshToken)) {
            return null; // 유효하지 않은 refreshToken
        }

        // 2. refreshToken으로 관리자 조회
        Member member = memberRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new NoSuchElementException("유효하지 않은 Refresh Token입니다."));

        // 3. 새로운 accessToken 생성
        UserDetails userDetails = userDetailsService.loadUserByUsername(member.getId());
        String newAccessToken = jwtUtil.generateAccessToken(userDetails.getUsername(), Map.of("roles", List.of(member.getRole().name())), member.getRole());
        long newAccessTokenExpiresIn = jwtUtil.getExpirationTimeFromAccessToken(newAccessToken);

        return AdminLoginResponseDto.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .expiresIn(newAccessTokenExpiresIn / 1000)
                .refreshExpiresIn(jwtUtil.getExpirationTimeFromRefreshToken(refreshToken) / 1000) // 기존 만료 시간 유지
                .id(member.getId())
                .build();
    }

}
