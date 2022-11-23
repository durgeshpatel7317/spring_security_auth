package com.springsecurityauth.service;

import com.springsecurityauth.entity.LoginUser;
import com.springsecurityauth.enums.Role;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Only used for UserDetailsManager
 */
@Service
@Slf4j
public class UserDetailsManagerService {

    @Autowired
    private final UserDetailsManager manager;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    public UserDetailsManagerService(UserDetailsManager manager, PasswordEncoder passwordEncoder) {
        this.manager = manager;
        this.passwordEncoder = passwordEncoder;
    }

    public UserDetails findOrCreateOAuth2User(String username, EnumSet<Role> roles) {
        UserDetails fetchedUser;
        try {
            fetchedUser = this.loadUserByUserName(username);
        } catch (UsernameNotFoundException e) {
            Set<String> authorities = roles.stream().map(Role::getValue).collect(Collectors.toSet());

            LoginUser user = new LoginUser();
            user.setUsername(username);
            // Setting the random password for OAuth2 authenticated user
            // It is needed to set the random password otherwise it can be a loophole
            // Where anyone who know the email of an OAuth2 Authenticated user may log in without password
            user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
            user.setAuthorities(authorities);

            manager.createUser(user);

            fetchedUser = user;
        }

        return fetchedUser;
    }

    public void createUser(LoginUser user) {
        Set<String> mappedAuth = Collections.singleton(Role.DEFAULT.getValue());
        if (user.getAuthorities() != null && user.getAuthorities().size() > 0) {
            // Validating and removing the user roles from list which does not exist in the enum
            mappedAuth = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(Role::of)
                    .filter(role -> !role.equals(Role.UNKNOWN))
                    .map(Role::getValue)
                    .collect(Collectors.toSet());
            // Setting the authority after removing the unknown ones
        }

        user.setAuthorities(mappedAuth);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        log.debug("Encoded password of the saved user is {} ", user.getPassword());

        manager.createUser(user);
    }

    public UserDetails loadUserByUserName(String username) {
        return manager.loadUserByUsername(username);
    }
}
