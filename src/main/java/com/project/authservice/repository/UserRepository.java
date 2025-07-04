package com.project.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.project.authservice.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    
    Optional<User> findByEmail(String email);
}
