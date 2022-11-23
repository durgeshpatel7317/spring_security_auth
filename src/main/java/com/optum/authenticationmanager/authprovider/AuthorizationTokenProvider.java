package com.optum.authenticationmanager.authprovider;

import com.optum.authenticationmanager.entity.auth.AuthorizationToken;
import com.optum.authenticationmanager.util.JwtUtilService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
public class AuthorizationTokenProvider implements AuthenticationProvider {

    @Autowired
    private final JwtUtilService jwtUtilService;

    public AuthorizationTokenProvider(JwtUtilService jwtUtilService) {
        this.jwtUtilService = jwtUtilService;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        try {
            Claims claims = jwtUtilService.parseJWT(authentication.getName());
            if (claims != null) {
                // Fetching the String roles from jwt token and converting it to GrantedAuthorities
                Set<GrantedAuthority> authorities = ((List<String>) claims.get("roles", ArrayList.class))
                        .stream()
                        .map(role -> new SimpleGrantedAuthority(role.toString()))
                        .collect(Collectors.toSet());

                return new AuthorizationToken(authentication.getName(), null, authorities);
            }
        } catch (JwtException exception) {
            log.error("Error occurred while parsing the jwt token and error is {} ", exception.getMessage());
            throw new BadCredentialsException("Expired or malformed authentication token");
        }
        throw new BadCredentialsException("Unauthorized user request...!");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AuthorizationToken.class.equals(authentication);
    }
}
