package com.springsecurityauth.dao;

import com.springsecurityauth.entity.LoginUser;
import com.springsecurityauth.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public class UserDao {

    @Autowired
    private final UserRepository userRepository;

    public UserDao(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void createUser(LoginUser user) {
        userRepository.save(user);
    }

    public Optional<LoginUser> loadUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public boolean userExists(String username) {
        return userRepository.userExists(username);
    }
}
