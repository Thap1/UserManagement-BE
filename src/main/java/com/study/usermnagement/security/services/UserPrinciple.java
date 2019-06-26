package com.study.usermnagement.security.services;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class UserPrinciple {

	private static final long serialVersionUID = 1L;
	private Long id;
	private String name;
	private String username;
	private String email;
	@JsonIgnore
	private String password;

	private Collection<? extends GrantedAuthority> authorities;
}
