package com.springsecurityauth.service;

import com.springsecurityauth.entity.UserSecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class TokenServiceImpl {
    private final List<UserSecretKey> userSecret;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    public TokenServiceImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.userSecret = new ArrayList<>();
    }

    public void saveUser(UserSecretKey userSecretKey) {
        UserSecretKey existingKey = this.getUser(userSecretKey.getUsername());
        userSecretKey.setKey(passwordEncoder.encode(userSecretKey.getKey()));

        if (existingKey == null) {
            userSecret.add(userSecretKey);
        } else {
            int index = userSecret.indexOf(existingKey);
            userSecret.set(index, userSecretKey);
        }
    }

    public UserSecretKey getUser(String username) {
        return userSecret
                .stream()
                .filter(user -> user.getUsername().equals(username))
                .findFirst().orElse(null);
    }

}
