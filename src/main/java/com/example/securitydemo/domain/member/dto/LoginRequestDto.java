package com.example.securitydemo.domain.member.dto;

import lombok.Data;

@Data
public class LoginRequestDto {
    private String username;
    private String password;
}
