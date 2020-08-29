package com.techstartingpoint.springboot.samples.jwtdemo.controller;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.techstartingpoint.springboot.samples.jwtdemo.dto.User;
import com.techstartingpoint.springboot.samples.jwtdemo.security.JWTTokenFactory;


@RestController
public class UserController {

	@PostMapping("user")
	public User login(@RequestParam("user") String username, @RequestParam("password") String password) {
		/*
		 * . Obviamente, para un proyecto real, en este punto deberíamos autenticar el usuario contra nuestra base de datos o contra cualquier proveedor externo.
		 */
		String token = JWTTokenFactory.getJWTToken(username);
		User user = new User();
		user.setUser(username);
		user.setToken(token);		
		return user;
		
	}

	
	@PostMapping("userOnExternalJWTIssuer")
	public User login3rdPart(@RequestParam("user") String username, @RequestParam("password") String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		/*
		 * . Obviamente, para un proyecto real, en este punto deberíamos autenticar el usuario contra nuestra base de datos o contra cualquier proveedor externo.
		 */
		String token = JWTTokenFactory.getJWTTokenThirdPartySchema(username);
		User user = new User();
		user.setUser(username);
		user.setToken(token);		
		return user;
		
	}
	
}