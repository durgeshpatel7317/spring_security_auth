package com.springsecurityauth.exceptions;

import com.springsecurityauth.enums.Status;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@ControllerAdvice
public class ApplicationExceptionHandler extends ResponseEntityExceptionHandler {

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

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException exception, HttpHeaders headers,
            HttpStatus status, WebRequest request) {
        Map<String, List<String>> body = new HashMap<>();

        List<String> errors = exception.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.toList());

        body.put("errors", errors);

        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }
}
