package com.complete.spring.security.completespringsecurity.controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.complete.spring.security.completespringsecurity.entity.UserEnt;
import com.complete.spring.security.completespringsecurity.repo.UserRepo;
import com.complete.spring.security.completespringsecurity.service.UserDetailsServiceImpl;
// import com.complete.spring.security.completespringsecurity.utils.JwtUtils;

@RestController
// @AllArgsConstructor
@RequestMapping(path = "/public")
public class PublicController {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;  

    // @Autowired
    // private JwtUtils jwtUtils;

    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/newuser")
    public void createUser(@RequestBody UserEnt user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles(Arrays.asList("USER"));
        userRepo.save(user);
    }
    @GetMapping("/all")
    public List<UserEnt> getAllUsers() {
        return userRepo.findAll();
    }

    @GetMapping(path = "find/{name}")
    public UserEnt findUserByName(@PathVariable String name) {
        return userRepo.findByUserName(name);
    }

    @DeleteMapping("delete/{userId}")
    public void deleteUser(@PathVariable Long userId ){
        userRepo.deleteById(userId);
    }

    // @PostMapping("login")
    // public String login(@RequestBody UserEnt user){
    //     try{

    //         authenticationManager.authenticate(
    //             new UsernamePasswordAuthenticationToken(
    //                 user.getUserName(), user.getPassword()));
    //         UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(user.getUserName());
    //         String jwt = jwtUtils.generateToken(userDetails.getUsername());
    //         return jwt;
    //     }catch(Exception e){
    //         throw new UsernameNotFoundException("Incorret username or pass");
    //     }

    // }
    
}
