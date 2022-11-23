package com.springsecurityauth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.Map;

@Component
@Slf4j
public class JwtUtilService {

    @Autowired
    private final JWTProperties jwtProperties;

    public JwtUtilService(JWTProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String generateJWTToken(String id, Map<String, Object> claims, String subject) {
        // Algorithm used for signing the jwt token
        SignatureAlgorithm algorithm = jwtProperties.algorithm;

        // Secret used for singing the token
        byte[] secretKeyBytes = DatatypeConverter.parseBase64Binary(jwtProperties.secret);
        Key signingKey = new SecretKeySpec(secretKeyBytes, algorithm.getJcaName());

        long dateNow = System.currentTimeMillis();

        return Jwts.builder().setId(id)
                .setIssuedAt(new Date(dateNow))
                .setSubject(subject)
                .setIssuer(jwtProperties.issuer)
                .addClaims(claims)
                .signWith(signingKey, algorithm)
                .setExpiration(new Date(dateNow + jwtProperties.expiryInHrs * 60 * 60 * 1000))
                .compact();
    }

    // Method to validate and read the JWT
    public Claims parseJWT(String jwt) {
        //This line will throw an exception if it is not a signed JWS (as expected)
        return Jwts.parserBuilder()
                .setSigningKey(DatatypeConverter.parseBase64Binary(jwtProperties.secret))
                .build()
                .parseClaimsJws(jwt).getBody();
    }

    @Configuration
    @ConfigurationProperties(prefix = "jwt")
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @FieldDefaults(level = AccessLevel.MODULE)
    public static class JWTProperties {
        SignatureAlgorithm algorithm;
        String secret;
        String issuer;
        Integer expiryInHrs;
    }
}
