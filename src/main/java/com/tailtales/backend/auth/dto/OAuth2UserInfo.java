package com.tailtales.backend.auth.dto;

public interface OAuth2UserInfo {

    String getId();
    String getName();
    String getEmail();
    String getImageUrl();
    String getProvider(); // "google", "kakao"

}
