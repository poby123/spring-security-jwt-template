package com.example.securitydemo.domain.member.service;

import com.example.securitydemo.domain.member.entity.Member;
import com.example.securitydemo.domain.member.exception.MemberException;
import com.example.securitydemo.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final MemberRepository memberRepository;

    public Member getUser(Long id){
        return memberRepository.findById(id).orElseThrow(MemberException.MemberNotFoundException::new);
    }

    public Member signUpUser(Member member){
        return memberRepository.save(member);
    }
}
