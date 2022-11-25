package com.springsecurityauth.service;

import com.springsecurityauth.dao.UserDao;
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
public class UserDetailsManagerImpl implements UserDetailsManager {

    @Autowired
    private final UserDao userDao;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    public UserDetailsManagerImpl(UserDao userDao, PasswordEncoder passwordEncoder) {
        this.userDao = userDao;
        this.passwordEncoder = passwordEncoder;
    }

    public UserDetails findOrCreateOAuth2User(String username, EnumSet<Role> roles) {
        boolean useExists = this.userExists(username);
        if (useExists) {
            return this.loadUserByUsername(username);
        } else {
            Set<String> authorities = roles.stream().map(Role::getValue).collect(Collectors.toSet());

            LoginUser user = new LoginUser();
            user.setUsername(username);
            // Setting the random password for OAuth2 authenticated user
            // It is needed to set the random password otherwise it can be a loophole
            // Where anyone who know the email of an OAuth2 Authenticated user may log in without password
            user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
            user.setAuthorities(authorities);
            user.setEnabled(true);

            userDao.createUser(user);

            return user;
        }
    }

    @Override
    public void createUser(UserDetails user) {
        LoginUser loginUser = (LoginUser) user;
        Set<String> mappedAuth = Collections.singleton(Role.USER.getValue());
        if (loginUser.getAuthorities() != null && loginUser.getAuthorities().size() > 0) {
            // Validating and removing the user roles from list which does not exist in the enum
            mappedAuth = loginUser.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(Role::of)
                    .filter(role -> !role.equals(Role.UNKNOWN))
                    .map(Role::getValue)
                    .collect(Collectors.toSet());
            // Setting the authority after removing the unknown ones
        }

        loginUser.setAuthorities(mappedAuth);
        loginUser.setPassword(passwordEncoder.encode(user.getPassword()));
        loginUser.setEnabled(true);

        userDao.createUser(loginUser);
    }

    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {
        return userDao.userExists(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDao.loadUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User with username " + username + " does not exist"));
    }
}
