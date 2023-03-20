package com.example.securitydemo.domain.member.exception;

import com.example.securitydemo.global.exception.BusinessException;

import static com.example.securitydemo.global.exception.ErrorCode.JWT_NOT_EXPIRED;

public class JwtNotExpiredException extends BusinessException {
        public JwtNotExpiredException(){
            super(JWT_NOT_EXPIRED);
        }

}
