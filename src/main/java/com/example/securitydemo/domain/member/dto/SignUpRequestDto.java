package com.example.securitydemo.domain.member.dto;

import com.example.securitydemo.domain.member.entity.Member;
import lombok.Data;
import org.springframework.security.crypto.password.PasswordEncoder;

@Data
public class SignUpRequestDto {

    private String username;
    private String name;
    private String password;
    private String email;

    public Member toEntity(PasswordEncoder passwordEncoder){
        return Member.builder()
                .username(username)
                .name(name)
                .password(passwordEncoder.encode(password))
                .email(email)
                .build();
    }
}
