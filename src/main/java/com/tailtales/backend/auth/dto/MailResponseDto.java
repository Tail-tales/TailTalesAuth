package com.tailtales.backend.auth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MailResponseDto {

    private String to;

    private String title;

    private String content;

}
