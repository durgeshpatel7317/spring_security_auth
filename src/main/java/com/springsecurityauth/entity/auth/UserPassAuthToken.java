package com.springsecurityauth.entity.auth;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UserPassAuthToken extends UsernamePasswordAuthenticationToken {

    public UserPassAuthToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public UserPassAuthToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
