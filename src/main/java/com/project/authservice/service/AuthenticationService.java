package com.project.authservice.service;

import com.project.authservice.dto.AuthRequest;
import com.project.authservice.dto.AuthResponse;
import com.project.authservice.entity.Role;
import com.project.authservice.entity.Token;
import com.project.authservice.entity.User;
import com.project.authservice.repository.RoleRepository;
import com.project.authservice.repository.TokenRepository;
import com.project.authservice.repository.UserRepository;
import com.project.authservice.security.JwtService; // JWT banane ke liye
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service  // Isko Spring service ke roop mein treat karega
@RequiredArgsConstructor  // Constructor injection ke liye (Lombok ka feature)
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager; 

    /**
     * User registration (Signup) ka method
     */
    public AuthResponse register(AuthRequest request) {

    // 1. Check karo ki email already registered to nahi hai
    if (userRepository.findByEmail(request.getEmail()).isPresent()) {
        throw new RuntimeException("Email already registered");
    }

    // 2. User ka password encrypt karo
    String encodedPassword = passwordEncoder.encode(request.getPassword());

    // 3. Default role uthao (ROLE_USER)
    Role userRole = roleRepository.findByName("ROLE_USER");

    // 4. Naya User object banao
    User user = User.builder()
            .firstname(request.getFirstname())
            .lastname(request.getLastname())
            .email(request.getEmail())
            .password(encodedPassword)
            .roles(List.of(userRole))
            .build();

    // 5. User database me save karo
    userRepository.save(user);

    // 6. JWT Token generate karo
    String jwtToken = jwtService.generateToken(user);

    // 7. Token ko save karo
    saveUserToken(user, jwtToken);

    // 8. Response return karo (better than just token)
    return AuthResponse.builder()
            .token(jwtToken)
            .build();
}


    /**
     * User Login (Authentication) ka method
     */
    public AuthResponse authenticate(AuthRequest request) {

        // 1. Authenticate user using Spring Security
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
    
        // 2. Email se user nikaalo
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));
    
        // 3. Purane tokens invalidate kar do
        revokeAllUserTokens(user);
    
        // 4. Naya token generate karo
        String jwtToken = jwtService.generateToken(user);
    
        // 5. Token save karo database me
        saveUserToken(user, jwtToken);
    
        // 6. Response return karo
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }
    
    /**
     * Helper method: User ke JWT token ko save karna
     */
    private void saveUserToken(User user, String jwtToken) {
        Token token = Token.builder()
                .user(user)
                .token(jwtToken)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    /**
     * Helper method: User ke existing tokens expire karna
     */
    private void revokeAllUserTokens(User user) {
        List<Token> validTokens = tokenRepository.findAllByUser(user);
        for (Token t : validTokens) {
            t.setExpired(true);
            t.setRevoked(true);
        }
        tokenRepository.saveAll(validTokens);
    }
}
