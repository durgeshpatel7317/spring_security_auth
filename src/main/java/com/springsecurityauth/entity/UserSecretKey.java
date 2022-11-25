package com.springsecurityauth.entity;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.Table;
import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Builder
@Entity
@Table(name = "secrets", indexes = {
        @Index(name = "uname", columnList = "username")
})
public class UserSecretKey {
    @Id
    @GeneratedValue
    Long id;

    @Column(nullable = false)
    String username;

    @Column(nullable = false)
    String otp;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    Status status;

    @Column(columnDefinition = "DATETIME", nullable = false)
    Instant issueTS;

    @Column(columnDefinition = "DATETIME", nullable = false)
    Instant expiryTS;

    public enum Status {
        SENT, VALIDATED, EXPIRED
    }
}
