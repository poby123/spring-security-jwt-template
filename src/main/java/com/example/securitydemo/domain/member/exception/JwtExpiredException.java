package com.example.securitydemo.domain.member.exception;

import com.example.securitydemo.global.exception.BusinessException;
import com.example.securitydemo.global.exception.ErrorCode;

public class JwtExpiredException extends BusinessException {
    public JwtExpiredException(){
        super(ErrorCode.JWT_EXPIRED);
    }
}
