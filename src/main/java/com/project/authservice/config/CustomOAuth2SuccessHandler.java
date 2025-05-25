package com.project.authservice.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.project.authservice.entity.User;
import com.project.authservice.repository.UserRepository;
import com.project.authservice.security.JwtService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                         HttpServletResponse response, 
                                         Authentication authentication) 
                                         throws IOException, ServletException {

        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        String email = oauthUser.getAttribute("email");

        User user = userRepository.findByEmail(email)
            .orElseGet(() -> {
                User newUser = User.builder()
                        .email(email)
                        .firstname("OAuth User")
                        .lastname("OAuth User")
                        .password("") // OAuth users ka password empty ya dummy hota hai
                        .build();
                return userRepository.save(newUser);
            });

        String jwtToken = jwtService.generateToken(user);
        
        response.setHeader("Authorization", "Bearer " + jwtToken);
        
        // Yahan pe redirect kar sakte ho kisi page pe agar chaho toh
        // response.sendRedirect("/home"); 
    }
}
