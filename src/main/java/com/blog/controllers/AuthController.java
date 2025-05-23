package com.blog.controllers;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.blog.payloads.JwtAuthRequest;
import com.blog.payloads.JwtAuthResponse;
import com.blog.payloads.UserDto;
import com.blog.security.JwtTokenHelper;
import com.blog.services.UserService;

import ch.qos.logback.core.subst.Token;

@RestController
@RequestMapping("/api/v1/auth/")
public class AuthController {

	@Autowired
	private JwtTokenHelper jwtTokenHelper;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserService userService;
	
	@PostMapping("/login")
	public ResponseEntity<JwtAuthResponse> createToken(@RequestBody JwtAuthRequest request) throws Exception
	{
		this.authenticate(request.getUsername(),request.getPassword());
		
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(request.getUsername());
//		System.out.println(userDetails);

		String token= this.jwtTokenHelper.generateToken(userDetails);
		System.out.println("Generated Token: " + token);
		JwtAuthResponse response = new JwtAuthResponse();
		
		response.setToken(token);
		
		return new ResponseEntity<JwtAuthResponse>(response,HttpStatus.OK);
	}

//	private void authenticate(String username, String password) throws Exception {
//		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
//		try
//		{
//		this.authenticationManager.authenticate(authenticationToken);
//		}
//		catch(BadCredentialsException e)
//		{
//			System.out.println("Invalid Details !!");
//			throw new Exception("Invalid Username or password !!");
//		}
//	}
	
	private void authenticate(String username, String password) throws Exception {
	    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
	    try {
	        // Try authenticating the user
	        this.authenticationManager.authenticate(authenticationToken);
	    } catch (BadCredentialsException e) {
	        // Log invalid credentials exception
	        System.out.println("Invalid details for username: " + username);
	        throw new Exception("Invalid username or password!");
	    } catch (Exception e) {
	        // Handle other possible exceptions
	        System.out.println("Authentication failed: " + e.getMessage());
	        throw new Exception("Authentication failed. Please try again!");
	    }
	}
	
	//register new user api
	
	@PostMapping("/register")
	public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto)
	{
		UserDto registeredUser = this.userService.registerNewUser(userDto);
		return new ResponseEntity<UserDto>(registeredUser,HttpStatus.CREATED);
	}

}
