package com.springsecurityauth.enums;


import lombok.Getter;

import java.util.Arrays;

@Getter
public enum Status {
    SUCCESS("Success"),
    FAILED("Failed"),
    UNKNOWN("Unknown");

    private final String value;

    Status(String status) {
        this.value = status;
    }

    public static Status of(String status) {
        return Arrays.stream(values())
                .filter(s -> s.value.equalsIgnoreCase(status))
                .findFirst()
                .orElse(Status.UNKNOWN);
    }
}
