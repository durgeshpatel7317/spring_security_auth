package com.springsecurityauth.repo;

import com.springsecurityauth.entity.LoginUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<LoginUser, Long> {
    Optional<LoginUser> findByUsername(String username);

    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM LoginUser u WHERE u.username = ?1")
    boolean userExists(String username);
}
