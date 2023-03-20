package com.example.securitydemo.domain.member.exception;

import com.example.securitydemo.global.exception.BusinessException;
import com.example.securitydemo.global.exception.ErrorCode;

public final class MemberException {
    public static class MemberNotFoundException extends BusinessException {
        public MemberNotFoundException(){
            super(ErrorCode.MEMBER_NOT_FOUND);
        }
    }
}
