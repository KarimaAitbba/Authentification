package com.grokonez.jwtauthentication.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestRestAPIs {
	
	@GetMapping("/api/test/user")
	@PreAuthorize("hasRole('USER') ")
	public String userAccess() {
		return ">>> welcom utilisateur!";
	}

	@GetMapping("/api/test/pm")
	@PreAuthorize("hasRole('PM') ")
	public String projectManagementAccess() {
		return ">>> welcom charge clientel";
	}
	
	@GetMapping("/api/test/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public String adminAccess() {
		return ">>>  welcom admin";
	}
}