package com.example.securitydemo.domain.member.dto;

import lombok.Builder;
import lombok.Data;

@Data
public class JwtResponseDto {
    private String type;
    private String accessToken;

    @Builder
    public JwtResponseDto(String type, String accessToken){
        this.type = type;
        this.accessToken = accessToken;
    }
}
