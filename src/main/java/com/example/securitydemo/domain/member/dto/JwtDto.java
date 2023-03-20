package com.example.securitydemo.domain.member.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class JwtDto {
    private String type;
    private String accessToken;
    private String refreshToken;
}
