package com.example.securitydemo.domain.member.repository.redis;

import com.example.securitydemo.domain.member.entity.redis.RefreshToken;
import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRedisRepository extends CrudRepository<RefreshToken, String> {
    List<RefreshToken> findAllByMemberId(Long memberId);

    Optional<RefreshToken> findByMemberIdAndValue(Long memberId, String value);

    Optional<RefreshToken> findByMemberIdAndId(Long memberId, String id);
}
