package com.spring.spring_rest.controller;



import java.util.Collections;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.spring_rest.dto.AuthLoginDto;
import com.spring.spring_rest.dto.AuthRoleRegisterDto;
import com.spring.spring_rest.dto.AuthUserRegisterDto;
import com.spring.spring_rest.entity.Auth_Role;
import com.spring.spring_rest.entity.Auth_User;
import com.spring.spring_rest.repository.AuthRoleRepository;
import com.spring.spring_rest.repository.AuthUserRepository;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
	
	private AuthenticationManager authenticationManager;
	private AuthUserRepository authUserRepo;
	private AuthRoleRepository authRoleRepo;
	private BCryptPasswordEncoder passwordEncoder;
	
	public AuthenticationController(AuthenticationManager authenticationManager, AuthUserRepository authUserRepo,
			AuthRoleRepository authRoleRepo, BCryptPasswordEncoder passwordEncoder) {
		this.authenticationManager = authenticationManager;
		this.authUserRepo = authUserRepo;
		this.authRoleRepo = authRoleRepo;
		this.passwordEncoder = passwordEncoder;
	}
	
	@PostMapping("/register_authorized_role")
	public ResponseEntity<String> register_authRole(
			@RequestBody AuthRoleRegisterDto authRoleRegisterDto) {
		if (authRoleRepo.existsByName(authRoleRegisterDto.getName())) {
			return new ResponseEntity<>(authRoleRegisterDto.getName() + " already created.",
					HttpStatus.BAD_REQUEST);
		}
		
		Auth_Role auth_role = new Auth_Role();
		auth_role.setName(authRoleRegisterDto.getName());
		
		authRoleRepo.save(auth_role);
		
		return new ResponseEntity<>(auth_role.getName() + " is successfully created", HttpStatus.OK);
	}
	
	@PostMapping("/register_authorized_user")
	public ResponseEntity<String> register_authUser(
			@RequestBody AuthUserRegisterDto authUserRegisterDto) {
		
		
		String username = authUserRegisterDto.getUsername() != null ? authUserRegisterDto.getUsername().trim() : "";
	    String password = authUserRegisterDto.getPassword() != null ? authUserRegisterDto.getPassword().trim() : "";
	    
	    // 2. Check if username or password are empty
	    if (username.isEmpty()) {
	        return new ResponseEntity<>("Username cannot be empty or just spaces.", HttpStatus.BAD_REQUEST);
	    }
	    if (password.isEmpty()) {
	        return new ResponseEntity<>("Password cannot be empty or just spaces.", HttpStatus.BAD_REQUEST);
	    }

	    // 3. Validate password length
	    if (password.length() < 8) {
	        return new ResponseEntity<>("Password must be at least 8 characters long.", HttpStatus.BAD_REQUEST);
	    }
		
		if (authUserRepo.existsByUsername(authUserRegisterDto.getUsername())) {
			return new ResponseEntity<>(authUserRegisterDto.getUsername() + 
					" is already taken.", HttpStatus.BAD_REQUEST);
		}
		
		Auth_User auth_user = new Auth_User();
		auth_user.setUsername(authUserRegisterDto.getUsername());
		auth_user.setPassword(passwordEncoder.encode(authUserRegisterDto.getPassword()));
		
		Auth_Role auth_role = authRoleRepo.findByName("USER")
				.orElseThrow(() -> new RuntimeException("Roles USER not found."));
		auth_user.setRoles(Collections.singletonList(auth_role));
		
		authUserRepo.save(auth_user);
		
		return new ResponseEntity<>(auth_user.getUsername() + " is successfully registered", HttpStatus.OK);
	}
	
	@PostMapping("/auth_login")
	public ResponseEntity<String> login(@RequestBody AuthLoginDto authLoginDto) {
	    
	    // 1. Check if the user even exists in the database
	    if (!authUserRepo.existsByUsername(authLoginDto.getUsername())) {
	        return new ResponseEntity<>("User does not exist.", HttpStatus.NOT_FOUND);
	    }

	    // 2. If they exist, attempt to authenticate their password
	    try {
	        Authentication authenticate = authenticationManager.authenticate(
	                new UsernamePasswordAuthenticationToken(
	                        authLoginDto.getUsername(),
	                        authLoginDto.getPassword()
	                )
	        );
	        
	        SecurityContextHolder.getContext().setAuthentication(authenticate);
	        return new ResponseEntity<>("Sign in successfully!", HttpStatus.OK);
	        
	    } catch (AuthenticationException e) {
	        // This catches wrong passwords (BadCredentialsException)
	        return new ResponseEntity<>("Incorrect password.", HttpStatus.UNAUTHORIZED);
	    }
	}
	

	public AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	public AuthUserRepository getAuthUserRepo() {
		return authUserRepo;
	}

	public void setAuthUserRepo(AuthUserRepository authUserRepo) {
		this.authUserRepo = authUserRepo;
	}

	public AuthRoleRepository getAuthRoleRepo() {
		return authRoleRepo;
	}

	public void setAuthRoleRepo(AuthRoleRepository authRoleRepo) {
		this.authRoleRepo = authRoleRepo;
	}

	public BCryptPasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}

	public void setPasswordEncoder(BCryptPasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	
	

}
