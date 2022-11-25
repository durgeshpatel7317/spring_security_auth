package com.springsecurityauth.service;

import com.springsecurityauth.dao.TokenDao;
import com.springsecurityauth.entity.UserSecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Random;

@Service
public class TokenServiceImpl {

    @Value("${otp.expiry.duration-seconds}")
    private String expiryDuration;

    @Autowired
    private final TokenDao tokenDao;

    public TokenServiceImpl(TokenDao tokenDao) {
        this.tokenDao = tokenDao;
    }

    public String generateOTP(String username) {
        UserSecretKey fetchedSecret = findExistingSecret(username);

        if (fetchedSecret == null) {
            return this.generateNewOTP(username);
        } else {
            return fetchedSecret.getOtp();
        }
    }

    private String generateNewOTP(String username) {
        String otp = (new Random().nextInt(999) * 1000) + "";
        Instant instant = Instant.now();

        UserSecretKey userSecretKey = UserSecretKey.builder()
                .username(username)
                .otp(otp)
                .status(UserSecretKey.Status.SENT)
                .issueTS(instant)
                .expiryTS(instant.plus(Long.parseLong(expiryDuration), ChronoUnit.SECONDS))
                .build();

        UserSecretKey savedSecret = tokenDao.save(userSecretKey);

        return savedSecret.getOtp();
    }

    public UserSecretKey findExistingSecret(String username) {
        List<UserSecretKey> userSecretKeys = tokenDao.findExistingSecrets(username, UserSecretKey.Status.SENT);
        if (userSecretKeys.size() == 0) {
            return null;
        }

        userSecretKeys.stream()
                .skip(1)
                .filter(this::isTokenExpired)
                .forEach(s -> this.updateTokenStatus(s.getId(), s.getUsername(), UserSecretKey.Status.EXPIRED));

        UserSecretKey latestToken = userSecretKeys.get(0);
        boolean tokenExpired = this.isTokenExpired(latestToken);
        if (tokenExpired) {
            this.updateTokenStatus(latestToken.getId(), latestToken.getUsername(), UserSecretKey.Status.EXPIRED);
            return null;
        } else {
            return latestToken;
        }
    }

    public void updateTokenStatus(Long id, String username, UserSecretKey.Status status) {
        tokenDao.updateTokenStatus(id, username, status);
    }

    private boolean isTokenExpired(UserSecretKey userSecretKey) {
        return Instant.now().compareTo(userSecretKey.getExpiryTS()) > 0;
    }

}
