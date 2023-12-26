package com.sparta.plusweek.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;


@Getter
public class UserRequestDto {

    @NotBlank
    @Pattern(regexp = "^[a-zA-Z0-9]{3,10}$")
    private String username;

    @NotBlank
    @Pattern(regexp = "^[a-zA-Z0-9]{4,15}$")
    private String password;

    @NotBlank
    @Pattern(regexp = "^[a-zA-Z0-9]{4,15}$")
    private String confirmPassword;

}