package com.project.authservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/oauth2")
public class OAuth2Controller {

    @GetMapping("/success")
    public ResponseEntity<String> oauth2Success(@RequestParam String token) {
        return ResponseEntity.ok("OAuth2 login successful! Token: " + token);
    }
}
