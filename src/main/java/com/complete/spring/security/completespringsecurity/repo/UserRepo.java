package com.complete.spring.security.completespringsecurity.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.complete.spring.security.completespringsecurity.entity.UserEnt;


@Repository
public interface UserRepo extends JpaRepository<UserEnt, Long> {

    UserEnt findByUserName(String username);
    
} 
