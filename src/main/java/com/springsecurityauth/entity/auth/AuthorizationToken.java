package com.springsecurityauth.entity.auth;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AuthorizationToken extends UsernamePasswordAuthenticationToken {

    public AuthorizationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public AuthorizationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
