package com.securegate.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {
    @NotBlank @Size(min = 3, max = 50)
    private String username;
    @NotBlank @Size(min = 3)
    private String password;
    @NotBlank @Email @Size(max = 100)
    private String email;
    private String role = "ROLE_USER";
}
