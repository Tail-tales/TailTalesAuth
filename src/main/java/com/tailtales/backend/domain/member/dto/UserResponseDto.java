package com.tailtales.backend.domain.member.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDto {

    private String provider;

    private String providerId;

    private String name;

    private String email;

    private String contact;

    private String role;

    private LocalDateTime createdAt;

    private String level;

    private String imgUrl;

}
