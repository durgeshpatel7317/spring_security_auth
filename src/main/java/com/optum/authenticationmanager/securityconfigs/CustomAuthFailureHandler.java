package com.optum.authenticationmanager.securityconfigs;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
public class CustomAuthFailureHandler implements AuthenticationFailureHandler {

    @Value("${spring.application.base-url}")
    private String appBaseUrl;

    @Value("${spring.security.auth.failure.redirect-url}")
    private String failureRedirectUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        log.error("Exception occurred while authenticating the user and error is {} ", exception.getMessage());

        response.setHeader(HttpHeaders.LOCATION, appBaseUrl + failureRedirectUrl);
        response.setStatus(HttpStatus.SEE_OTHER.value());
    }
}
