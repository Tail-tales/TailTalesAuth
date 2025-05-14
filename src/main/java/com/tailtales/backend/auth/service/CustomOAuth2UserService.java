package com.tailtales.backend.auth.service;

import com.tailtales.backend.auth.dto.GoogleOAuth2UserInfo;
import com.tailtales.backend.auth.dto.KakaoOAuth2UserInfo;
import com.tailtales.backend.auth.dto.OAuth2UserInfo;
import com.tailtales.backend.auth.util.JwtUtil;
import com.tailtales.backend.domain.member.entity.Member;
import com.tailtales.backend.domain.member.entity.MemberRole;
import com.tailtales.backend.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Log4j2
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        OAuth2UserInfo oauth2UserInfo;
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        if (registrationId.equals("kakao")) {
            oauth2UserInfo = new KakaoOAuth2UserInfo(oAuth2User.getAttributes());
        } else if (registrationId.equals("google")) {
            oauth2UserInfo = new GoogleOAuth2UserInfo(oAuth2User.getAttributes());
        } else {
            throw new OAuth2AuthenticationException("지원하지 않는 소셜 로그인입니다: " + registrationId);
        }

        String provider = oauth2UserInfo.getProvider();
        String providerId = oauth2UserInfo.getId();
        String email = oauth2UserInfo.getEmail();
        String nickname = oauth2UserInfo.getName();
        String imageUrl = oauth2UserInfo.getImageUrl();

        Optional<Member> memberOptional = memberRepository.findByProviderAndProviderId(provider, providerId);
        Member member;
        String refreshToken = jwtUtil.generateRefreshToken(); // Refresh Token 먼저 생성

        if (memberOptional.isPresent()) {
            member = memberOptional.get();
            // 기존 사용자일 경우 Refresh Token 업데이트 (toBuilder 사용)
            member = member.toBuilder()
                    .refreshToken(refreshToken)
                    .build();
            memberRepository.save(member);
        } else {
            // 새로운 사용자일 경우 Refresh Token과 함께 저장 (insertMember에서 Builder 사용)
            member = insertMember(provider, providerId, email, nickname, imageUrl, refreshToken);
        }

        String accessToken = jwtUtil.generateAccessToken(member.getProviderId(),
                Map.of("nickname", member.getName(), "email", member.getEmail()), // claims
                member.getRole());

        Map<String, Object> customAttributes = new HashMap<>(oAuth2User.getAttributes());
        customAttributes.put("accessToken", accessToken);
        customAttributes.put("refreshToken", refreshToken);
        customAttributes.put("nickname", member.getName());
        customAttributes.put("email", member.getEmail());
        customAttributes.put("imgUrl", member.getImgUrl());

        return new DefaultOAuth2User(
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                customAttributes,
                userNameAttributeName
        );
    }

    private Member insertMember(String provider, String providerId, String email, String nickname, String imgUrl, String refreshToken) {
        Member member = Member.builder()
                .provider(provider)
                .providerId(providerId)
                .email(email)
                .name(nickname)
                .role(MemberRole.ROLE_USER)
                .password(passwordEncoder.encode(nickname))
                .imgUrl(imgUrl)
                .refreshToken(refreshToken)
                .build();
        return memberRepository.save(member);
    }

}
