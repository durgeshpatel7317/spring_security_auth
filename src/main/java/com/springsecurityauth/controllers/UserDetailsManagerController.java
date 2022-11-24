package com.springsecurityauth.controllers;

import com.springsecurityauth.entity.LoginUser;
import com.springsecurityauth.enums.Status;
import com.springsecurityauth.service.UserDetailsManagerImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

/**
 * Only used for UserDetailsManager
 */
@RestController
@RequestMapping("/api/v1")
public class UserDetailsManagerController {

    @Autowired
    private final UserDetailsManagerImpl userDetailsManagerImpl;

    public UserDetailsManagerController(UserDetailsManagerImpl userDetailsManagerImpl) {
        this.userDetailsManagerImpl = userDetailsManagerImpl;
    }

    @PostMapping("/user")
    public ResponseEntity<Object> createUser(@Valid @RequestBody LoginUser user) {
        userDetailsManagerImpl.createUser(user);

        Map<String, Object> response = new HashMap<>();
        response.put("status", Status.SUCCESS.getValue());
        response.put("message", "User account created successfully.. !");

        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }
}
