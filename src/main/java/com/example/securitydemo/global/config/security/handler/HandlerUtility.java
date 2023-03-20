package com.example.securitydemo.global.config.security.handler;

import com.example.securitydemo.global.exception.ErrorCode;
import com.example.securitydemo.global.exception.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

public class HandlerUtility {
    public static void writeResponse(HttpServletRequest request, HttpServletResponse response, ErrorCode errorCode) throws IOException, ServletException{
        response.setStatus(errorCode.getStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        try(OutputStream os = response.getOutputStream()){
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.writeValue(os, ErrorResponse.of(errorCode));
            os.flush();
        }
    }

    public static void writeResponse(HttpServletRequest request, HttpServletResponse response, ResponseEntity responseEntity) throws IOException, ServletException{
        response.setStatus(responseEntity.getStatusCodeValue());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        try(OutputStream os = response.getOutputStream()){
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.writeValue(os, responseEntity);
            os.flush();
        }
    }
}
