package com.example.securitydemo.domain.member.entity.redis;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.concurrent.TimeUnit;


@RedisHash("refresh_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {

    @Id
    @Indexed
    private String id;

    @Indexed
    private String value;

    @Indexed
    private Long memberId;

    private LocalDateTime lastUpdateDate;

    @TimeToLive(unit = TimeUnit.DAYS)
    private Long timeout = 7L;

    @Builder
    public RefreshToken(Long memberId, String value){
        this.memberId = memberId;
        this.value = value;
        this.lastUpdateDate = LocalDateTime.now(ZoneId.of("Asia/Seoul"));
    }

    public void updateToken(String newToken){
        this.lastUpdateDate = LocalDateTime.now(ZoneId.of("Asia/Seoul"));
        this.value = newToken;
    }
}
