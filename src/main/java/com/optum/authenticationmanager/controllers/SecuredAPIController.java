package com.optum.authenticationmanager.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1")
public class SecuredAPIController {

    @GetMapping("/employees")
    public ResponseEntity<Object> getEmployees() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Request is successful..!");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/resources")
    public ResponseEntity<Object> getResources(Authentication authentication) {
        log.debug("Value of authentication object being stored in security context is {} ", authentication);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Request is successful..!");
        return ResponseEntity.ok(response);
    }
}
