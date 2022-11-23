package com.springsecurityauth.securityconfigs;

import com.springsecurityauth.authprovider.AuthorizationTokenProvider;
import com.springsecurityauth.authprovider.SecretKeyAuthProvider;
import com.springsecurityauth.authprovider.UsernamePassAuthProvider;
import com.springsecurityauth.enums.Role;
import com.springsecurityauth.filters.CustomAuthenticationFilter;
import com.springsecurityauth.filters.CustomAuthorizationFilter;
import com.springsecurityauth.filters.CustomLoginFilter;
import com.springsecurityauth.service.TokenServiceImpl;
import com.springsecurityauth.util.JwtUtilService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig implements WebMvcConfigurer {

    @Autowired
    private final TokenServiceImpl tokenService;

    @Autowired
    private final UsernamePassAuthProvider usernamePassAuthProvider;

    @Autowired
    private final SecretKeyAuthProvider secretKeyAuthProvider;

    @Autowired
    private final JwtUtilService jwtUtilService;

    @Autowired
    private final AuthorizationTokenProvider authorizationTokenProvider;

    public SecurityConfig(
            TokenServiceImpl tokenService,
            UsernamePassAuthProvider usernamePassAuthProvider,
            SecretKeyAuthProvider secretKeyAuthProvider,
            JwtUtilService jwtUtilService,
            AuthorizationTokenProvider authorizationTokenProvider
    ) {
        this.tokenService = tokenService;
        this.usernamePassAuthProvider = usernamePassAuthProvider;
        this.secretKeyAuthProvider = secretKeyAuthProvider;
        this.jwtUtilService = jwtUtilService;
        this.authorizationTokenProvider = authorizationTokenProvider;
    }

    @Bean
    // If we are using the custom AuthenticationManager
    // It is mandatory to expose the bean for each of the authentication provider and register with AuthenticationManager
    // Here we are using the default AuthenticationProvider for OAuth2 but is required to expose and register
    public OAuth2LoginAuthenticationProvider oauth2AuthProvider() {
        return new OAuth2LoginAuthenticationProvider(
                new DefaultAuthorizationCodeTokenResponseClient(),
                new DefaultOAuth2UserService()
        );
    }

    @Bean
    // Refer: https://www.baeldung.com/spring-security-multiple-auth-providers
    public AuthenticationManager authenticationManager(HttpSecurity http, OAuth2LoginAuthenticationProvider oauth2AuthProvider) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(usernamePassAuthProvider)
                .authenticationProvider(secretKeyAuthProvider)
                .authenticationProvider(authorizationTokenProvider)
                .authenticationProvider(oauth2AuthProvider)
                .build();
    }

    @Bean
    // Refer: https://stackoverflow.com/questions/59648314/antmatchers-allow-admin-all-routes-while-other-roles-are-restricted
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy(Arrays.stream(Role.values()).map(Role::getValue).collect(Collectors.joining(" > ")));
        return hierarchy;
    }

    @Bean
    // It will be responsible for handling the authentication failures
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomAuthFailureHandler();
    }

    @Bean
    // OAuth2 implementation References
    // https://medium.com/swlh/spring-boot-oauth2-login-with-github-88b178e0c004
    // https://www.baeldung.com/spring-security-5-oauth2-login
    // https://www.callicoder.com/spring-boot-security-oauth2-social-login-part-1/
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            AuthenticationManager authenticationManager,
            AuthenticationFailureHandler authenticationFailureHandler
    ) throws Exception {
        return httpSecurity
                .authorizeRequests(
                        request -> request
                                .antMatchers(
                                        "/api/v1/user/**",
                                        "/api/v1/login",
                                        "/api/v1/authenticate/**",
                                        "/api/v1/oauth/login/*"
                                )
                                .permitAll()
                )
                .csrf() // csrf needs to be disabled in order to access the
                .disable()
                .formLogin()
                .disable()
                .oauth2Login(
                        login -> login
                                .loginPage("/api/v1/oauth/login/*")// By Default Application base URL is the login URL for Oauth
                                .defaultSuccessUrl("/api/v1/oauth/login/success", true)
                                .failureHandler(authenticationFailureHandler)
                )
                .authorizeRequests(
                        request -> request
                                .antMatchers(HttpMethod.GET, "/api/v1/resources/**") // Both User and admin can access the requests specified here
                                .hasAuthority(Role.USER.getValue()) // It is possible because role hierarchy is already defined above
                )
                .authorizeRequests(
                        request -> request
                                .antMatchers(HttpMethod.GET, "/api/v1/employees/**") // Only admin can access the requests specified here
                                .hasAuthority(Role.ADMIN.getValue())
                                .anyRequest()
                                .authenticated()
                )
                .authenticationManager(authenticationManager)
                .addFilterBefore(new CustomAuthorizationFilter(authenticationManager), BasicAuthenticationFilter.class) // Added the custom filter
                .addFilterBefore(new CustomAuthenticationFilter(authenticationManager, jwtUtilService), BasicAuthenticationFilter.class) // Added the custom filter
                .addFilterAt(new CustomLoginFilter(authenticationManager, tokenService), BasicAuthenticationFilter.class) // Added the custom filter
                .httpBasic()
                .and()
                .build();
    }

}
