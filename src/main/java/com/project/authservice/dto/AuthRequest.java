package com.project.authservice.dto;

import lombok.Data;

@Data
public class AuthRequest {
    private String firstname;
    private String lastname;
    private String email;
    private String password;
}
