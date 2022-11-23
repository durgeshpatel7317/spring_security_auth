package com.optum.authenticationmanager.authprovider;

import com.optum.authenticationmanager.entity.auth.UserPassAuthToken;
import com.optum.authenticationmanager.service.UserDetailsManagerService;
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
public class UsernamePassAuthProvider implements AuthenticationProvider {

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Autowired
    private final UserDetailsManagerService userDetailsManagerService;

    public UsernamePassAuthProvider(PasswordEncoder passwordEncoder, UserDetailsManagerService userDetailsManagerService) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsManagerService = userDetailsManagerService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("Value of username in authentication object is {} ", authentication.getName());

        // Load the user details by username from DB
        UserDetails user = userDetailsManagerService.loadUserByUserName(authentication.getName());

        String credential = authentication.getCredentials() == null ? "" : authentication.getCredentials().toString();

        if (passwordEncoder.matches(credential, user.getPassword())) {
            return new UserPassAuthToken(user.getUsername(), user.getPassword());
        }

        throw new BadCredentialsException("Bad credentials..!");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UserPassAuthToken.class.equals(authentication);
    }
}
