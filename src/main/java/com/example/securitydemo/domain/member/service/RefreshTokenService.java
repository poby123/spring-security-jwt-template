package com.example.securitydemo.domain.member.service;

import com.example.securitydemo.domain.member.entity.redis.RefreshToken;
import com.example.securitydemo.domain.member.exception.JwtInvalidException;
import com.example.securitydemo.domain.member.repository.redis.RefreshTokenRedisRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRedisRepository refreshTokenRedisRepository;

    @Transactional
    public void addRefreshToken(Long memberId, String tokenValue) {
        final RefreshToken refreshToken = RefreshToken.builder()
                .memberId(memberId)
                .value(tokenValue)
                .build();

        refreshTokenRedisRepository.save(refreshToken);
    }

    @Transactional(readOnly = true)
    public Optional<RefreshToken> findRefreshToken(Long memberId, String value) {
        return refreshTokenRedisRepository.findByMemberIdAndValue(memberId, value);
    }

    @Transactional
    public void deleteRefreshToken(RefreshToken refreshToken) {
        refreshTokenRedisRepository.delete(refreshToken);
    }

    @Transactional
    public void deleteRefreshTokenByValue(Long memberId, String value) {
        final RefreshToken refreshToken = refreshTokenRedisRepository.findByMemberIdAndValue(memberId, value)
                .orElseThrow(JwtInvalidException::new);
        refreshTokenRedisRepository.delete(refreshToken);
    }

    @Transactional
    public void deleteRefreshTokenByMemberIdAndId(Long memberId, String id) {
        final RefreshToken refreshToken = refreshTokenRedisRepository.findByMemberIdAndId(memberId, id)
                .orElseThrow(JwtInvalidException::new);
        refreshTokenRedisRepository.delete(refreshToken);
    }

}
