package com.springsecurityauth.authprovider;

import com.springsecurityauth.entity.auth.SecretKeyAuthToken;
import com.springsecurityauth.entity.UserSecretKey;
import com.springsecurityauth.service.TokenServiceImpl;
import com.springsecurityauth.service.UserDetailsManagerService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class SecretKeyAuthProvider implements AuthenticationProvider {

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Autowired
    private final TokenServiceImpl tokenService;

    @Autowired
    private final UserDetailsManagerService userDetailsManagerService;

    public SecretKeyAuthProvider(PasswordEncoder passwordEncoder, TokenServiceImpl tokenService, UserDetailsManagerService userDetailsManagerService) {
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.userDetailsManagerService = userDetailsManagerService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("Value of username in authentication object is {} ", authentication.getName());

        // Load the 2-factor token by username from DB
        UserSecretKey userAuthTokenObj = tokenService.getUser(authentication.getName());
        if (userAuthTokenObj == null) {
            throw new BadCredentialsException("Invalid username or token..!");
        }

        String credential = authentication.getCredentials() == null ? "" : authentication.getCredentials().toString();

        // Load user details object from DB to get the user role for setting into the authentication obj
        if (passwordEncoder.matches(credential, userAuthTokenObj.getKey())) {
            UserDetails userObj = userDetailsManagerService.loadUserByUserName(authentication.getName());
            return new SecretKeyAuthToken(userObj.getUsername(), null, userObj.getAuthorities());
        }

        throw new BadCredentialsException("Invalid username or token..!");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SecretKeyAuthToken.class.equals(authentication);
    }
}
