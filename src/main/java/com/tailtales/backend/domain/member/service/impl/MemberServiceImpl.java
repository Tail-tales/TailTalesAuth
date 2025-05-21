package com.tailtales.backend.domain.member.service.impl;

import com.tailtales.backend.domain.member.dto.AdminInsertRequestDto;
import com.tailtales.backend.domain.member.dto.AdminResponseDto;
import com.tailtales.backend.domain.member.dto.AdminUpdateRequestDto;
import com.tailtales.backend.domain.member.dto.UserResponseDto;
import com.tailtales.backend.domain.member.entity.Member;
import com.tailtales.backend.domain.member.entity.MemberRole;
import com.tailtales.backend.domain.member.repository.MemberRepository;
import com.tailtales.backend.domain.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // 관리자 회원가입
    @Override
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

    // 관리자 정보 조회
    @Override
    public AdminResponseDto getAdminInfo(String id) {

        Member member = memberRepository.findById(id, MemberRole.ROLE_ADMIN)
                .orElseThrow(() -> new IllegalArgumentException("해당 관리자를 찾을 수 없습니다."));

        return AdminResponseDto.builder()
                .name(member.getName())
                .id(member.getId())
                .password(member.getPassword())
                .email(member.getEmail())
                .contact(member.getContact())
                .build();

    }

    // 관리자 정보 수정
    @Override
    public void updateAdminInfo(String id, AdminUpdateRequestDto dto) {

        Member member = memberRepository.findById(id, MemberRole.ROLE_ADMIN)
                .orElseThrow(() -> new IllegalArgumentException("해당 관리자를 찾을 수 없습니다."));

        Member.MemberBuilder memberBuilder = member.toBuilder();
        boolean changed = false;

        if (dto.getName() != null) {
            memberBuilder.name(dto.getName());
            changed = true;
        }
        if (dto.getPassword() != null) {
            memberBuilder.password(bCryptPasswordEncoder.encode(dto.getPassword()));
            changed = true;
        }
        if (dto.getContact() != null) {
            memberBuilder.contact(dto.getContact());
            changed = true;
        }
        if (dto.getEmail() != null) {
            memberBuilder.email(dto.getEmail());
            changed = true;
        }

        if (changed) {
            memberRepository.save(memberBuilder.build());
        }

    }

    // 관리자 계정 삭제
    @Override
    public void deleteAdmin(String id) {

        Member member = memberRepository.findById(id, MemberRole.ROLE_ADMIN)
                .orElseThrow(() -> new IllegalArgumentException("해당 관리자를 찾을 수 없습니다."));

        member = member.toBuilder()
                .deletedAt(LocalDateTime.now())
                .isDeleted(true)
                .build();
        memberRepository.save(member);

    }

    // 전체 사용자 조회
    @Override
    public List<UserResponseDto> getUsers() {

        List<Member> members = memberRepository.findAllNotDeleted(MemberRole.ROLE_USER);
        return members.stream()
                .map(member -> UserResponseDto.builder()
                        .provider(member.getProvider())
                        .providerId(member.getProviderId())
                        .name(member.getName())
                        .email(member.getEmail())
                        .contact(member.getContact())
                        .role(member.getRole().toString())
                        .createdAt(member.getCreatedAt())
                        .level(member.getLevel().toString())
                        .imgUrl(member.getImgUrl())
                        .build())
                .collect(Collectors.toList());

    }

    // 개별 사용자 조회
    @Override
    public Optional<UserResponseDto> getUserInfo(String provider, String providerId) {

        return memberRepository.findByProviderAndProviderId(provider, providerId)
                .map(member -> UserResponseDto.builder()
                        .provider(member.getProvider())
                        .providerId(member.getProviderId())
                        .name(member.getName())
                        .email(member.getEmail())
                        .contact(member.getContact())
                        .role(member.getRole().toString())
                        .createdAt(member.getCreatedAt())
                        .level(member.getLevel().toString())
                        .imgUrl(member.getImgUrl())
                        .build());

    }

    // 유저 탈퇴 처리
    @Override
    public void deleteUser(String provider, String providerId) {

        Member member = memberRepository.findByProviderAndProviderId(provider, providerId)
                .orElseThrow(() -> new IllegalArgumentException("해당 사용자를 찾을 수 없습니다."));

        member = member.toBuilder()
                .deletedAt(LocalDateTime.now())
                .isDeleted(true)
                .build();
        memberRepository.save(member);

    }

}
