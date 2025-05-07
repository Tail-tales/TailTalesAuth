package com.tailtales.backend.domain.member.service.impl;

import com.tailtales.backend.domain.member.dto.AdminInsertRequestDto;
import com.tailtales.backend.domain.member.dto.AdminResponseDto;
import com.tailtales.backend.domain.member.dto.AdminUpdateRequestDto;
import com.tailtales.backend.domain.member.entity.Member;
import com.tailtales.backend.domain.member.entity.MemberRole;
import com.tailtales.backend.domain.member.repository.MemberRepository;
import com.tailtales.backend.domain.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

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

    public void updateAdminInfo(String id, AdminUpdateRequestDto dto) {

        Member member = memberRepository.findById(id, MemberRole.ROLE_ADMIN)
                .orElseThrow(() -> new IllegalArgumentException("해당 관리자를 찾을 수 없습니다."));

        Member.MemberBuilder memberBuilder = member.toBuilder();
        boolean changed = false;

        if (dto.getName() != null && !member.getName().equals(dto.getName())) {
            memberBuilder.name(dto.getName());
            changed = true;
        }
        if (dto.getPassword() != null && !bCryptPasswordEncoder.matches(dto.getPassword(), member.getPassword())) {
            memberBuilder.password(bCryptPasswordEncoder.encode(dto.getPassword()));
            changed = true;
        }
        if (dto.getContact() != null && !member.getContact().equals(dto.getContact())) {
            memberBuilder.contact(dto.getContact());
            changed = true;
        }
        if (dto.getEmail() != null && !member.getEmail().equals(dto.getEmail())) {
            memberBuilder.email(dto.getEmail());
            changed = true;
        }

        if (changed) {
            memberRepository.save(memberBuilder.build());
        }

    }

    public void deleteAdmin(String id) {

        Member member = memberRepository.findById(id, MemberRole.ROLE_ADMIN)
                .orElseThrow(() -> new IllegalArgumentException("해당 관리자를 찾을 수 없습니다."));

        member = member.toBuilder()
                .isDeleted(true)
                .build();
        memberRepository.save(member);

    }

}
