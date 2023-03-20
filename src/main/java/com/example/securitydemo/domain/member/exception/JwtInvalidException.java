package com.example.securitydemo.domain.member.exception;

import com.example.securitydemo.global.exception.BusinessException;
import com.example.securitydemo.global.exception.ErrorCode;

public class JwtInvalidException extends BusinessException {
    public JwtInvalidException(){
        super(ErrorCode.JWT_INVALID);
    }
}
