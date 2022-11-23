package com.optum.authenticationmanager.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.optum.authenticationmanager.entity.auth.UserPassAuthToken;
import com.optum.authenticationmanager.entity.UserSecretKey;
import com.optum.authenticationmanager.enums.Status;
import com.optum.authenticationmanager.service.TokenServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.PathContainer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.pattern.PathPatternParser;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.stream.Stream;

/**
 * Can't make it a component because it has dependency on AuthenticationManager bean,
 * AuthenticationManager bean has a dependency on AuthenticationConfiguration bean which is injected during creation of SecurityFilterChain
 * So we are injecting this filter through the constructor instead of using component
 * Will be used for token based authentication mechanism
 */
@Slf4j
public class CustomLoginFilter extends OncePerRequestFilter {

    @Autowired
    private final AuthenticationManager authenticationManager;

    @Autowired
    private final TokenServiceImpl tokenService;

    public CustomLoginFilter(AuthenticationManager authenticationManager, TokenServiceImpl tokenService) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }

    @Override
    public void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain) throws IOException {
        String username = req.getHeader("username");
        String password = req.getHeader("password");

        try {
            // Create the authentication object
            Authentication auth = new UserPassAuthToken(username, password);
            // Delegate the authentication object to authentication manager
            Authentication authenticationResponse = authenticationManager.authenticate(auth);

            // Generating and saving the user with secret key in DB
            UserSecretKey userSecretKey = new UserSecretKey();
            String secretKey = (new Random().nextInt(999) * 1000) + "";
            userSecretKey.setKey(secretKey);
            userSecretKey.setUsername(authenticationResponse.getName());
            tokenService.saveUser(userSecretKey);

            // Returning the key in response header for now
            // TODO: Later the key should be pushed to the user either as OTP or push notification
            res.setHeader("token", secretKey);
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
        long matchCount = Stream.of("/api/v1/login")
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
