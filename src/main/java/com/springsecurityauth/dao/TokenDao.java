package com.springsecurityauth.dao;

import com.springsecurityauth.entity.UserSecretKey;
import com.springsecurityauth.repo.UserSecretsRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
public class TokenDao {

    @Autowired
    private final UserSecretsRepo repo;

    public TokenDao(UserSecretsRepo repo) {
        this.repo = repo;
    }

    public UserSecretKey save(UserSecretKey userSecretKey) {
        return repo.save(userSecretKey);
    }

    public List<UserSecretKey> findExistingSecrets(String username, UserSecretKey.Status status) {
        return repo.findAlreadyGeneratedOTP(username, status);
    }

    @Transactional
    public void updateTokenStatus(Long id, String username, UserSecretKey.Status status) {
        repo.updateTokenStatus(id, username, status);
    }
}
