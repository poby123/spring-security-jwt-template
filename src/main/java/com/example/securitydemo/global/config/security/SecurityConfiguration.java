package com.example.securitydemo.global.config.security;

import com.example.securitydemo.domain.member.service.CustomUserDetailsService;
import com.example.securitydemo.global.config.security.filter.CustomExceptionHandleFilter;
import com.example.securitydemo.global.config.security.filter.CustomUsernamePasswordAuthenticationFilter;
import com.example.securitydemo.global.config.security.filter.JwtAuthenticationFilter;
import com.example.securitydemo.global.config.security.filter.ReissueAuthenticationFilter;
import com.example.securitydemo.global.config.security.handler.CustomAccessDeniedHandler;
import com.example.securitydemo.global.config.security.handler.CustomAuthenticationEntryPoint;
import com.example.securitydemo.global.config.security.handler.CustomAuthenticationFailureHandler;
import com.example.securitydemo.global.config.security.handler.CustomAuthenticationSuccessHandler;
import com.example.securitydemo.global.config.security.provider.JwtAuthenticationProvider;
import com.example.securitydemo.global.config.security.provider.ReissueAuthenticationProvider;
import com.example.securitydemo.global.result.ResultCode;
import com.example.securitydemo.global.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.*;

import static com.example.securitydemo.domain.member.entity.Role.ROLE_USER;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtUtil jwtUtil;

    // handlers
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    // providers
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final ReissueAuthenticationProvider reissueAuthenticationProvider;

    // filter
    private final CustomExceptionHandleFilter customExceptionHandleFilter;


    private static final String[] AUTH_WHITELIST_STATIC = {"/static/css/**", "/static/js/**", "*.ico"};
    private static final String[] AUTH_WHITELIST_SWAGGER = {
            "/swagger-ui/**"
    };
    private static final String[] AUTH_WHITELIST = {
            "/login", "/reissue", "/signup"
    };

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());
        daoAuthenticationProvider.setUserDetailsService(customUserDetailsService);

        return daoAuthenticationProvider;
    }

    @Bean
    public CustomUsernamePasswordAuthenticationFilter customUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        final CustomUsernamePasswordAuthenticationFilter filter = new CustomUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(customAuthenticationFailureHandler);

        return filter;
    }

    @Bean
    JwtAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        final List<String> skipPaths = new ArrayList<>();
        skipPaths.addAll(Arrays.asList(AUTH_WHITELIST));
        skipPaths.addAll(Arrays.asList(AUTH_WHITELIST_STATIC));
        skipPaths.addAll(Arrays.asList(AUTH_WHITELIST_SWAGGER));

        final RequestMatcher matcher = new CustomRequestMatcher(skipPaths);
        final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(matcher, jwtUtil);
        filter.setAuthenticationManager(authenticationManager);

        return filter;
    }

    @Bean
    ReissueAuthenticationFilter reissueAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        final ReissueAuthenticationFilter filter = new ReissueAuthenticationFilter(jwtUtil);
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(customAuthenticationFailureHandler);

        return filter;
    }

    @Bean
    public CorsConfigurationSource configurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .antMatchers(AUTH_WHITELIST_SWAGGER)
                .antMatchers(AUTH_WHITELIST_STATIC);
    }

    private void configureCustomBeans() {
        final Map<String, ResultCode> map = new HashMap<>();
        map.put("/login", ResultCode.LOGIN_SUCCESS);
        map.put("/reissue", ResultCode.REISSUE_SUCCESS);
        map.put("/login/recovery", ResultCode.LOGIN_WITH_CODE_SUCCESS);
        customAuthenticationSuccessHandler.setResultCodeMap(map);
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(bCryptPasswordEncoder)
                .and()
                .authenticationProvider(jwtAuthenticationProvider)
                .authenticationProvider(reissueAuthenticationProvider)
                .build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        configureCustomBeans();

         // http config
        http.exceptionHandling()
                .authenticationEntryPoint(customAuthenticationEntryPoint)
                .accessDeniedHandler(customAccessDeniedHandler);
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.logout().disable()
                .formLogin().disable()
                .httpBasic().disable();

        http.cors()
                .configurationSource(configurationSource())
                .and()
                .csrf()
                .disable()
                .authenticationManager(authenticationManager)
                .authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest)
                .permitAll()
                .antMatchers(AUTH_WHITELIST)
                .permitAll()
                .anyRequest().hasAuthority(ROLE_USER.toString());

        http.addFilterBefore(jwtAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(customExceptionHandleFilter, JwtAuthenticationFilter.class);
        http.addFilterBefore(customUsernamePasswordAuthenticationFilter(authenticationManager), JwtAuthenticationFilter.class);
        http.addFilterBefore(reissueAuthenticationFilter(authenticationManager), JwtAuthenticationFilter.class);

        return http.build();
    }
}
