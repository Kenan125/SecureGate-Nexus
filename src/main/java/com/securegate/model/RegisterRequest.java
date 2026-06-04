package com.securegate.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {
    @NotBlank @Size(min = 3, max = 50)
    private String username;
    @NotBlank @Size(min = 8)
    private String password;
    private String role = "ROLE_USER";
}
