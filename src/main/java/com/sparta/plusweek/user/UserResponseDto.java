package com.sparta.plusweek.user;

import lombok.Getter;

@Getter
public class UserResponseDto {
    private final String username;
    public UserResponseDto(User user) {
        this.username = user.getUsername();
    }
}