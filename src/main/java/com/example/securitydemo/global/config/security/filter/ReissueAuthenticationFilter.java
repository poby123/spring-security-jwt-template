package com.example.securitydemo.global.config.security.filter;

import com.example.securitydemo.domain.member.exception.JwtInvalidException;
import com.example.securitydemo.global.config.security.token.ReissueAuthenticationToken;
import com.example.securitydemo.global.util.JwtUtil;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;


public class ReissueAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private JwtUtil jwtUtil;
    private static final AntPathRequestMatcher ANT_PATH_REQUEST_MATCHER
            = new AntPathRequestMatcher("/reissue", "POST");

    public ReissueAuthenticationFilter(JwtUtil jwtUtil) {
        super(ANT_PATH_REQUEST_MATCHER);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            if (request.getCookies() == null) {
                throw new JwtInvalidException();
            }
            final String accessToken = jwtUtil.extractJwt(request);

            final Cookie refreshToken = Arrays.stream(request.getCookies())
                    .filter(c -> c.getName().equals("refreshToken"))
                    .findFirst()
                    .orElseThrow(JwtInvalidException::new);
            final ReissueAuthenticationToken authRequest = ReissueAuthenticationToken.of(refreshToken.getValue(), accessToken);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }

}
