package com.project.authservice.security;

import com.project.authservice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

// @Service annotation: Spring ko batata hai ye ek Service class hai
@Service
public class JwtService {

    // Secret key generate kar rahe hain (normally secure config se aata hai)
    private static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // Token ka expire time (e.g., 24 hours)
    private static final long EXPIRATION_TIME = 24 * 60 * 60 * 1000;

    /**
     * Token generate karta hai User object ke basis pe
     */
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("roles", user.getRoles());

        return createToken(claims, user.getEmail());
    }

    /**
     * Private method to create JWT token
     */
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)              // Extra data dalna (email, roles)
                .setSubject(subject)             // Subject ka matlab usually user ka unique id/email
                .setIssuedAt(new Date(System.currentTimeMillis())) // Kab issue hua
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // Kab expire hoga
                .signWith(key)                   // Sign the token with our secret key
                .compact();                      // Token bana do
    }

    /**
     * User ka email extract karne ke liye
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Token se kisi bhi claim ko extract karne ke liye
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Token ko validate karta hai (expiry + username check)
     */
    public boolean isTokenValid(String token, User user) {
        final String username = extractUsername(token);
        return (username.equals(user.getEmail()) && !isTokenExpired(token));
    }

    /**
     * Token expire hua ya nahi, check karne ke liye
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Token ka expiration time extract karta hai
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Internal method to parse token and get all claims
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)              // Token ko validate karne ke liye secret key use
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
