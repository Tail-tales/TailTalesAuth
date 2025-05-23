package com.tailtales.backend.domain.member.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AdminResponseDto {

    private String name;
    private String id;
    private String password;
    private String email;
    private String contact;

}
