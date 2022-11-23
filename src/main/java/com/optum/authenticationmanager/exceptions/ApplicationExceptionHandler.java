package com.optum.authenticationmanager.exceptions;

import com.optum.authenticationmanager.enums.Status;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@ControllerAdvice
public class ApplicationExceptionHandler {

    @Value("${spring.application.base-url}")
        private String appBaseUrl;

    @Value("${spring.security.auth.failure.redirect-url}")
    private String failureRedirectUrl;

    @ExceptionHandler(value = IllegalArgumentException.class)
    public ResponseEntity<Object> handleIllegalArgumentException(IllegalArgumentException exception) {
        Map<String, Object> error = new HashMap<>();
        error.put("status", Status.FAILED.getValue());
        error.put("error", exception.getMessage());

        return ResponseEntity.badRequest().body(error);
    }

    @ExceptionHandler(value = AuthFailureException.class)
    public ResponseEntity<Object> handleAuthFailureException(AuthFailureException exception) {
        Map<String, Object> error = new HashMap<>();
        error.put("status", Status.FAILED.getValue());
        error.put("error", exception.getMessage());

        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header(HttpHeaders.LOCATION, appBaseUrl + failureRedirectUrl)
                .body(error);
    }

    @ExceptionHandler(value = Exception.class)
    public ResponseEntity<Object> handleException(Exception exception) {
        log.error("Generic exception occurred {} and exception is {} ", Exception.class.getName(), exception.getMessage());
        Map<String, Object> error = new HashMap<>();
        error.put("status", Status.FAILED.getValue());
        error.put("error", "Something went wrong, please try again later");

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
