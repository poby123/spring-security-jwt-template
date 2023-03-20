package com.example.securitydemo.domain.member.controller;

import com.example.securitydemo.domain.member.dto.SignUpRequestDto;
import com.example.securitydemo.domain.member.entity.Member;
import com.example.securitydemo.domain.member.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @GetMapping("/user/{userId}")
    public Member getUser(@PathVariable("userId")Long userId){
        return userService.getUser(userId);
    }

    @PostMapping("/signup")
    public Member postUser(@RequestBody SignUpRequestDto dto){
        log.info("signup req: {}", dto);
        return userService.signUpUser(dto.toEntity(passwordEncoder));
    }
}
