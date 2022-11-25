package com.springsecurityauth.repo;

import com.springsecurityauth.entity.UserSecretKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserSecretsRepo extends JpaRepository<UserSecretKey, Long> {

    @Query(value = "SELECT u FROM UserSecretKey u WHERE u.username = ?1 AND u.status = ?2 ORDER BY u.issueTS DESC")
    List<UserSecretKey> findAlreadyGeneratedOTP(String username, UserSecretKey.Status status);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("UPDATE UserSecretKey SET status = ?3 WHERE id = ?1 AND username = ?2")
    void updateTokenStatus(Long id, String username, UserSecretKey.Status status);
}
