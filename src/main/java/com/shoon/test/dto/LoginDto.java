package com.shoon.test.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginDto {

    @NotNull
    @Size(min = 3, max = 30)
    private String username;

    @NotNull
    @Size(min = 3, max = 100)
    private String password;
}
