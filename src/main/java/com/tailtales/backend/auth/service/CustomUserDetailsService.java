package com.tailtales.backend.auth.service;

import com.tailtales.backend.domain.member.entity.Member;
import com.tailtales.backend.domain.member.entity.MemberRole;
import com.tailtales.backend.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        Optional<Member> memberOptional;

        // providerId로 먼저 검색 (소셜 로그인 사용자의 경우)
        memberOptional = memberRepository.findByProviderId(identifier);

        // providerId로 찾지 못하면 일반 아이디로 검색 (자체 로그인 또는 관리자)
        if (memberOptional.isEmpty()) {
            memberOptional = memberRepository.findById(identifier);
        }

        Member member = memberOptional.orElseThrow(() -> new UsernameNotFoundException(identifier + "와 같은 아이디를 가진 회원을 찾을 수 없습니다."));

        if (member.isDeleted()) {
            throw new UsernameNotFoundException("삭제된 계정입니다.");
        }

        String username = member.getProviderId() != null ? member.getProviderId() : member.getId();

        String password = member.getPassword();

        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(member.getRole().name()));

        return new User(username, password, authorities);
    }


}
