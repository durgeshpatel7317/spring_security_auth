package com.springsecurityauth.authprovider;

import com.springsecurityauth.entity.auth.UserPassAuthToken;
import com.springsecurityauth.service.UserDetailsManagerImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class UsernamePassAuthProvider implements AuthenticationProvider {

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Autowired
    private final UserDetailsManagerImpl userDetailsManagerImpl;

    public UsernamePassAuthProvider(PasswordEncoder passwordEncoder, UserDetailsManagerImpl userDetailsManagerImpl) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsManagerImpl = userDetailsManagerImpl;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            log.debug("Value of username in authentication object is {} ", authentication.getName());

            // Load the user details by username from DB
            UserDetails user = userDetailsManagerImpl.loadUserByUsername(authentication.getName());

            String credential = authentication.getCredentials() == null ? "" : authentication.getCredentials().toString();

            if (passwordEncoder.matches(credential, user.getPassword())) {
                return new UserPassAuthToken(user.getUsername(), user.getPassword());
            }
        } catch (UsernameNotFoundException exception) {
            log.error(exception.getMessage());
        }

        throw new BadCredentialsException("Bad credentials..!");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UserPassAuthToken.class.equals(authentication);
    }
}
