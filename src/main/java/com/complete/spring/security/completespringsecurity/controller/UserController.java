package com.complete.spring.security.completespringsecurity.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.complete.spring.security.completespringsecurity.entity.UserEnt;
import com.complete.spring.security.completespringsecurity.repo.UserRepo;

@RestController
@RequestMapping(path = "/user")
public class UserController {
    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    private UserRepo userRepo;

    @GetMapping
    public List<UserEnt> getAllUsers() {
        return userRepo.findAll();
    }

    @PutMapping
    public ResponseEntity<?> updateUser(@RequestBody UserEnt user) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();
        UserEnt userInDB = userRepo.findByUserName(userName);
        userInDB.setUserName(user.getUserName());
        userInDB.setPassword(user.getPassword());
        userInDB.setPassword(passwordEncoder.encode(user.getPassword()));
        // userInDB.setRoles(Arrays.asList("USER"));
        userRepo.save(userInDB);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

}
