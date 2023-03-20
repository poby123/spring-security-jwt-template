package com.example.securitydemo.global.exception;

import lombok.Getter;
import org.springframework.validation.FieldError;

import java.util.ArrayList;
import java.util.List;

@Getter
public class ErrorResponse {
    private int status;
    private String code;
    private String message;

    private List<FieldError> errors = new ArrayList<>();

    private ErrorResponse(final ErrorCode errorCode){
        this.status = errorCode.getStatus();
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
    }

    private ErrorResponse(final ErrorCode errorCode, List<FieldError> errors){
        this.status = errorCode.getStatus();
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
        this.errors = errors;
    }

    public static ErrorResponse of(BusinessException be){
        return new ErrorResponse(be.getErrorCode());
    }

    public static ErrorResponse of(ErrorCode errorCode){
        return new ErrorResponse(errorCode);
    }

    public static ErrorResponse of(ErrorCode errorCode, List<FieldError> errors){
        return new ErrorResponse(errorCode, errors);
    }
}
