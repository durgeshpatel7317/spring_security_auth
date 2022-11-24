package com.springsecurityauth.enums;

import lombok.Getter;

import java.util.Arrays;

@Getter
public enum Role {
    ADMIN("Admin"),
    USER("User"),
    UNKNOWN("Unknown");
    private final String value;

    Role(String value) {
        this.value = value;
    }

    public static Role of(String role) {
        return Arrays.stream(values())
                .filter(v -> v.getValue().equalsIgnoreCase(role))
                .findFirst()
                .orElse(Role.UNKNOWN);
    }
}
