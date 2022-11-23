package com.springsecurityauth.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springsecurityauth.entity.auth.SecretKeyAuthToken;
import com.springsecurityauth.enums.Status;
import com.springsecurityauth.util.JwtUtilService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.PathContainer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.pattern.PathPatternParser;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private final AuthenticationManager authenticationManager;

    @Autowired
    private final JwtUtilService jwtUtilService;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager, JwtUtilService jwtUtilService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtilService = jwtUtilService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain) throws IOException {
        String username = req.getHeader("username");
        String token = req.getHeader("token");

        log.debug("Custom filter is invoked, provided token is {} ", token);
        try {
            Authentication auth = new SecretKeyAuthToken(username, token);

            // Authentication obj returned after authentication is completed by the authentication provider
            Authentication authResponse = authenticationManager.authenticate(auth);

            // Getting the allowed roles as string from authorities
            Set<String> allowedUserRoles = authResponse.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            Map<String, Object> jwtTokenClaims = new HashMap<>();
            jwtTokenClaims.put("username", username);
            jwtTokenClaims.put("roles", allowedUserRoles);

            String authToken = jwtUtilService.generateJWTToken(username, jwtTokenClaims, username);
            res.setHeader("Authorization", "Bearer " + authToken);
        } catch (AuthenticationException exception) {
            log.error("Error occurred while authenticating the user and error is {} ", exception.getMessage());

            // Ref: https://stackoverflow.com/questions/34595605/how-to-manage-exceptions-thrown-in-filters-in-spring
            res.setStatus(HttpStatus.UNAUTHORIZED.value());
            res.setContentType("application/json");

            Map<String, Object> errorDTO = new HashMap<>();
            errorDTO.put("status", Status.FAILED.getValue());
            errorDTO.put("error", exception.getMessage());

            ObjectMapper mapper = new ObjectMapper();
            PrintWriter out = res.getWriter();
            out.print(mapper.writeValueAsString(errorDTO));
            out.flush();
        }

        // Here we are not calling the filter chain
        // Because it is a two-factor authentication
        // We will hold the authentication in security context holder and proceed with further filter chain in next custom filter
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        PathContainer pathContainer = PathContainer.parsePath(request.getRequestURI());
        // This filter will filter the request which follow the following pattern
        // Other requests will not be filtered by this filter
        long matchCount = Stream.of("/api/v1/authenticate/**")
                .map(path -> {
                    PathPatternParser patternParser = new PathPatternParser();
                    patternParser.setMatchOptionalTrailingSeparator(true);
                    return patternParser.parse(path);
                })
                .filter(pathPattern -> pathPattern.matches(pathContainer))
                .count();
        return matchCount == 0;
    }
}
