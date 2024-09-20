package com.complete.spring.security.completespringsecurity.controller;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.complete.spring.security.completespringsecurity.entity.UserEnt;
import com.complete.spring.security.completespringsecurity.repo.UserRepo;

@RestController
@RequestMapping("admin")
public class AdminController {

    private UserRepo userRepo;

    @GetMapping("all")
    public List<UserEnt> getAllUsers() {
        return userRepo.findAll();
    }
}
