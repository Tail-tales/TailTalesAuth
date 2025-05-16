package com.tailtales.backend.auth.service;

import com.tailtales.backend.auth.dto.AdminLoginResponseDto;
import com.tailtales.backend.auth.dto.MailResponseDto;
import com.tailtales.backend.auth.dto.UserLoginResponseDto;
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
import java.util.UUID;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final MemberRepository memberRepository;
    private final SimpleMailMessageService simpleMailMessageService;

    // 관리자 아이디 중복체크
    public boolean isDuplicateId(String id) { return memberRepository.existsById(id); }

    // 관리자, 사용자 이메일 중복체크
    public boolean isDuplicateEmail(String email) { return memberRepository.existsByEmail(email); }

    // 관리자 로그인
    public AdminLoginResponseDto login(String id, String password) {

        // 사용자 인증 (AuthenticationManager 사용)
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(id, password)
        );

        // 인증 성공 시 JWT 토큰 생성
        if (authentication.isAuthenticated()) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(id);
            Member member = memberRepository.findById(id, MemberRole.ROLE_ADMIN)
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

    // 관리자 로그아웃
    public void logout(String id) {

        Member member = memberRepository.findById(id, MemberRole.ROLE_ADMIN)
                .orElseThrow(() -> new NoSuchElementException("해당 아이디의 관리자를 찾을 수 없습니다."));

        Member updatedMember = member.toBuilder()
                .refreshToken(null)
                .build();

        memberRepository.save(updatedMember);

    }

    // 관리자 토큰 재발급
    public AdminLoginResponseDto refreshAdminAccessToken(String refreshToken) {

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

    // 사용자 토큰 재발급
    public UserLoginResponseDto refreshUserAccessToken(String refreshToken) {

        // 1. refreshToken 유효성 검증
        if (!jwtUtil.validateRefreshToken(refreshToken)) {
            return null; // 유효하지 않은 refreshToken
        }

        // 2. refreshToken으로 사용자 조회
        Member member = memberRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new NoSuchElementException("유효하지 않은 Refresh Token입니다."));

        // 3. 새로운 accessToken 생성
        String newAccessToken = jwtUtil.generateAccessToken(
                member.getProviderId(),
                Map.of("name", member.getName(), "email", member.getEmail()), // claims
                member.getRole()
        );
        long newAccessTokenExpiresIn = jwtUtil.getExpirationTimeFromAccessToken(newAccessToken);
        long refreshTokenExpiresIn = jwtUtil.getExpirationTimeFromRefreshToken(refreshToken); // 기존 refreshToken 만료 시간 유지

        return UserLoginResponseDto.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .expiresIn(newAccessTokenExpiresIn / 1000)
                .refreshExpiresIn(refreshTokenExpiresIn / 1000)
                .name(member.getName())
                .email(member.getEmail())
                .build();
    }

    // 관리자 비밀번호 찾기
    public void sendMail(String id) {
        Member member = memberRepository.findById(id, MemberRole.ROLE_ADMIN)
                .orElseThrow(() -> new NoSuchElementException("해당 아이디의 관리자를 찾을 수 없습니다."));

        // 1. 임시 비밀번호 생성
        String newPassword = generateRandomPassword();
        String encodedPassword = bCryptPasswordEncoder.encode(newPassword);

        // 2. DB에 새로운 비밀번호 저장
        Member updatedMember = member.toBuilder()
                .password(encodedPassword)
                .build();
        memberRepository.save(updatedMember);

        // 3. MailResponseDto 생성
        MailResponseDto mailResponseDto = MailResponseDto.builder()
                .to(member.getEmail())
                .title("새로운 비밀번호 안내")
                .content("새로운 비밀번호는 다음과 같습니다: " + newPassword + "\n로그인 후 반드시 비밀번호를 변경해주세요.")
                .build();

        // 4. 이메일 발송
        simpleMailMessageService.sendEmail(mailResponseDto.getTo(), mailResponseDto.getTitle(), mailResponseDto.getContent());

    }

    private String generateRandomPassword() {
        // UUID를 사용하여 임시 비밀번호 생성 (길이 조절 가능)
        return UUID.randomUUID().toString().substring(0, 12);
    }

}
