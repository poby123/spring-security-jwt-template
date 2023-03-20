package com.example.securitydemo.domain.member.exception;

import com.example.securitydemo.global.exception.BusinessException;
import com.example.securitydemo.global.exception.ErrorCode;

public class LogoutByAnotherException extends BusinessException {
    public LogoutByAnotherException() {
        super(ErrorCode.LOGOUT_BY_ANOTHER);
    }
}
