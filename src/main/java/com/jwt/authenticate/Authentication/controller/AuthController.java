package com.jwt.authenticate.Authentication.controller;

import com.jwt.authenticate.Authentication.dto.LoginRequest;
import com.jwt.authenticate.Authentication.dto.LoginResponse;
import com.jwt.authenticate.Authentication.service.CustomUserDetailsService;
import com.jwt.authenticate.Authentication.service.jwt.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final JwtService jwtService;

    public AuthController(AuthenticationManager authenticationManager, CustomUserDetailsService userDetailsService, JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
    }
    
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request){

       authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));

       UserDetails userDetails =
               userDetailsService.loadUserByUsername(request.getUsername());
       String token =jwtService.generateToken(userDetails);
       return ResponseEntity.ok(new LoginResponse(token));

    }
}
