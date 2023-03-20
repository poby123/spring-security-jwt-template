package com.example.securitydemo.global.config.security.token;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class ReissueAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public ReissueAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }


    public static ReissueAuthenticationToken of(String refreshToken, String accessToken){
        return new ReissueAuthenticationToken(refreshToken, accessToken);
    }
}
