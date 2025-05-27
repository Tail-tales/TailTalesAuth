package com.tailtales.backend.auth.dto;

import java.util.Map;

public class KakaoOAuth2UserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attributes;
    private final Map<String, Object> kakaoAccount;
    private final Map<String, Object> profile;

    @SuppressWarnings("unchecked")
    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
        Object kakaoAccountObj = attributes.get("kakao_account");
        if (kakaoAccountObj instanceof Map) {
            this.kakaoAccount = (Map<String, Object>) kakaoAccountObj;
            Object profileObj = this.kakaoAccount.get("profile");
            if (profileObj instanceof Map) {
                this.profile = (Map<String, Object>) profileObj;
            } else {
                this.profile = Map.of();
            }
        } else {
            this.kakaoAccount = Map.of();
            this.profile = Map.of();
        }
    }

    @Override
    public String getId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getName() {
        return (String) profile.get("nickname");
    }

    @Override
    public String getEmail() {
        return (String) kakaoAccount.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) profile.get("profile_image_url");
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

}
