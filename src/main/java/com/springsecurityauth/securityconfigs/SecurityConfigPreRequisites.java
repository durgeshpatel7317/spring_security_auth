package com.springsecurityauth.securityconfigs;

import com.springsecurityauth.dao.UserDao;
import com.springsecurityauth.service.UserDetailsManagerImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration
public class SecurityConfigPreRequisites {

    @Autowired
    private final UserDao userDao;

    public SecurityConfigPreRequisites(UserDao userDao) {
        this.userDao = userDao;
    }

    /**
     * Here we can use JDBCUserDetailsManager if we have to get users from DB for authentication purpose
     *
     * @return
     */
    @Bean
    public UserDetailsManager userDetailsManager(PasswordEncoder passwordEncoder) {
        return new UserDetailsManagerImpl(userDao, passwordEncoder);
    }

    /**
     * It will allow to encode the password before saving
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
