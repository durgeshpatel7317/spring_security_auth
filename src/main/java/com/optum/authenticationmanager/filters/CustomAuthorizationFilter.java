package com.optum.authenticationmanager.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.optum.authenticationmanager.entity.auth.AuthorizationToken;
import com.optum.authenticationmanager.enums.Status;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.PathContainer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.pattern.PathPatternParser;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Autowired
    private final AuthenticationManager authenticationManager;

    @Autowired

    public CustomAuthorizationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain) throws IOException, ServletException {
        String authorization = req.getHeader("Authorization");
        try {
            if (authorization != null && authorization.startsWith("Bearer ")) {
                String token = authorization.substring(7);
                // Create the authentication object
                Authentication auth = new AuthorizationToken(token, null);
                // Delegate the authentication object to authentication manager
                Authentication authenticationResponse = authenticationManager.authenticate(auth);
                if (authenticationResponse != null && authenticationResponse.isAuthenticated()) {
                    SecurityContextHolder.getContext().setAuthentication(authenticationResponse);
                }
            }
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

            return;
        }

        // Continue with the regular filter chain
        // This is done for APIs which requires the user to be authenticated
        filterChain.doFilter(req, res);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // This filter will not be invoked if below url patterns are accessed
        PathContainer pathContainer = PathContainer.parsePath(request.getRequestURI());
        long matchCount = Stream.of("/api/v1/user/**", "/api/v1/login", "/api/v1/authenticate/**")
                .map(path -> {
                    PathPatternParser patternParser = new PathPatternParser();
                    patternParser.setMatchOptionalTrailingSeparator(true);
                    return patternParser.parse(path);
                })
                .filter(pathPattern -> pathPattern.matches(pathContainer))
                .count();
        return matchCount > 0;
    }
}
