package com.optum.authenticationmanager.securityconfigs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.Collections;

@Configuration
public class SecurityConfigPreRequisites {

    /**
     * Here we can use JDBCUserDetailsManager if we have to get users from DB for authentication purpose
     *
     * @return
     */
    @Bean
    public UserDetailsManager userDetailsManager() {
        return new InMemoryUserDetailsManager(Collections.emptyList());
    }

    /**
     * It will allow to encode the passoword before saving
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
