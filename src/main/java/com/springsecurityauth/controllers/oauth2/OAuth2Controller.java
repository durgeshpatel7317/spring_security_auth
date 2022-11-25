package com.springsecurityauth.controllers.oauth2;

import com.springsecurityauth.enums.Role;
import com.springsecurityauth.exceptions.AuthFailureException;
import com.springsecurityauth.service.UserDetailsManagerImpl;
import com.springsecurityauth.util.JwtUtilService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/v1")
public class OAuth2Controller {

    @Value("${spring.application.base-url}")
    private String appBaseUrl;

    @Value("${spring.security.auth.success.redirect-url}")
    private String successRedirectUrl;

    @Value("${spring.security.auth.base-url}")
    private String authorizationBaseUrl;

    @Value("${spring.security.github.user-email-uri}")
    private String githubUserEmailUri;

    @Autowired
    private final ClientRegistrationRepository registrationRepository;

    @Autowired
    private final OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private final UserDetailsManagerImpl userDetailsManagerImpl;

    @Autowired
    private final JwtUtilService jwtUtilService;

    public OAuth2Controller(ClientRegistrationRepository registrationRepository, OAuth2AuthorizedClientService authorizedClientService, UserDetailsManagerImpl userDetailsManagerImpl, JwtUtilService jwtUtilService) {
        this.registrationRepository = registrationRepository;
        this.authorizedClientService = authorizedClientService;
        this.userDetailsManagerImpl = userDetailsManagerImpl;
        this.jwtUtilService = jwtUtilService;
    }


    /**
     * @param client   name of the OAuth2 client with which authentication is supposed to happen
     * @param response set the location header in response with authorization URL if OAuth2 client is found
     * @return redirect to authorization URL if client is found else return an error response
     */
    @GetMapping("/oauth/login/{client}")
    public ResponseEntity<Object> getAvailableOAuth2LoginClients(@PathVariable("client") String client, HttpServletResponse response) {

        ClientRegistration registration = registrationRepository.findByRegistrationId(client.toLowerCase());
        if (registration != null) {
            response.setHeader(HttpHeaders.LOCATION, String.valueOf(URI.create(appBaseUrl + authorizationBaseUrl + registration.getRegistrationId())));
            return ResponseEntity.status(HttpStatus.SEE_OTHER).body(Optional.empty());
        }
        return ResponseEntity.badRequest().body(Collections.singletonMap("error", "No authorization client present, check the client name and try again..!"));
    }

    /**
     * This API will be invoked when authentication will be successful for the user
     * 1. Here we will make an API call to OAuth2 provider client to get the user email
     * 2. Make a call to check and save the user to DB
     * 3. Make a call to @JwtUtilService to generate the JWT token
     * 4. Add the JWT token as Bearer token as Authorization header in API response header
     */
    @SuppressWarnings("unchecked")
    @GetMapping("/oauth/login/success")
    public ResponseEntity<Object> getUserDetailsAndCreateToken(OAuth2AuthenticationToken authenticationToken, HttpServletResponse response) {

        OAuth2AuthorizedClient authorizedClient = authorizedClientService
                .loadAuthorizedClient(authenticationToken.getAuthorizedClientRegistrationId(), authenticationToken.getName());

        if (authorizedClient == null) {
            throw new AuthFailureException("Error occurred while authentication, please try again");
        }

        // Can be used for the purpose of getting the URL for making user profile API call to OAuth2 APIs
        String useInfoEndpoint = authorizedClient
                .getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUri();

        if (useInfoEndpoint != null && !useInfoEndpoint.isEmpty()) {
            String accessToken = authorizedClient.getAccessToken().getTokenValue();

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
            HttpEntity<String> entity = new HttpEntity<>("", headers);

            RestTemplate restTemplate = new RestTemplate();
            // Making a call to OAuth2 provider to get the user email
            ResponseEntity<Map> userInfoResponse = restTemplate.exchange(useInfoEndpoint, HttpMethod.GET, entity, Map.class);

            Map<String, Object> userInfo = userInfoResponse.getBody();

            if (authorizedClient
                    .getClientRegistration()
                    .getRegistrationId()
                    .equalsIgnoreCase("github")) {

                String userEmail = this.getUserPrimaryEmail(accessToken, githubUserEmailUri);
                log.debug("Found email of the user {} ", userEmail);

                if (userEmail != null) {
                    UserDetails user = userDetailsManagerImpl.findOrCreateOAuth2User(userEmail, EnumSet.of(Role.USER));
                    String token = this.getJwtToken(user);

                    // Creating the cookie and adding JWT token as cookie in the response
                    Cookie cookie = new Cookie("_token", token);
                    cookie.setPath("/");
                    cookie.setHttpOnly(true);

                    response.addCookie(cookie);
                    response.setHeader(HttpHeaders.LOCATION, appBaseUrl + successRedirectUrl);
                } else {
                    throw new AuthFailureException("Error occurred while authentication, please try again");
                }
            }
            return ResponseEntity.status(HttpStatus.SEE_OTHER).body(userInfo);
        } else {
            throw new AuthFailureException("Error occurred while authentication, please try again");
        }
    }

    private String getJwtToken(UserDetails user) {
        // Getting the allowed roles as string from user
        Set<String> allowedUserRoles = user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        Map<String, Object> jwtTokenClaims = new HashMap<>();
        jwtTokenClaims.put("username", user.getUsername());
        jwtTokenClaims.put("roles", allowedUserRoles);

        return jwtUtilService.generateJWTToken(user.getUsername(), jwtTokenClaims, user.getUsername());
    }

    /**
     * 1. Make an API call to GitHub users email API to get the email of users
     * 2. Filter and find the object where email is primary
     *
     * @param accessToken token
     * @param emailUri    GitHub API to get the user emails
     * @return email string
     */
    @SuppressWarnings("unchecked")
    private String getUserPrimaryEmail(String accessToken, String emailUri) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        HttpEntity<String> entity = new HttpEntity<>("", headers);

        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<List> userEmailResponse = restTemplate.exchange(emailUri, HttpMethod.GET, entity, List.class);

        List<Map<String, Object>> userEmailList = (List<Map<String, Object>>) userEmailResponse.getBody();
        if (userEmailList == null) {
            return null;
        }
        return userEmailList
                .stream()
                .filter(e -> Boolean.parseBoolean(e.get("primary").toString()))
                .findFirst()
                .orElse(new HashMap<>())
                .get("email").toString();
    }

//    This can be used If we have UI for login where we can provide the buttons to login for each of the OAuth2 providers
//    It is constructing the authorization Url for OAuth registered clients
//    @GetMapping("/login/oauth")
//    @SuppressWarnings("unchecked")
//    public ResponseEntity<Object> getAvailableOAuth2LoginClients() {
//
//        Map<String, Object> authUrl = new HashMap<>();
//
//        Iterable<ClientRegistration> clientRegistrations = null;
//        ResolvableType type = ResolvableType.forInstance(registrationRepository)
//                .as(Iterable.class);
//        if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
//            clientRegistrations = (Iterable<ClientRegistration>) registrationRepository;
//        }
//
//        if(clientRegistrations == null) {
//            return ResponseEntity.ok(Collections.emptyList());
//        }
//
//        clientRegistrations.forEach(registration -> authUrl.put(registration.getClientName(), authorizationBaseUrl + "/" + registration.getRegistrationId()));
//
//        return ResponseEntity.ok(Collections.singletonList(authUrl));
//
//    }
}
