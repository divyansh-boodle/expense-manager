package com.project.authservice.repository;

import com.project.authservice.entity.Token;
import com.project.authservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    List<Token> findAllByUser(User user);

    Optional<Token> findByToken(String token);
}