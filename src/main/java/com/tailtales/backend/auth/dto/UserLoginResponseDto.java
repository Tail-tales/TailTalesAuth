package com.tailtales.backend.auth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserLoginResponseDto {

    private String accessToken;

    private String refreshToken;

    @Builder.Default
    private String tokenType = "Bearer";

    private long expiresIn;

    private long refreshExpiresIn;

    private String name;

    private String email;

}
