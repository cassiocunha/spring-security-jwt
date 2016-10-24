package com.monkeyhand.security.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.monkeyhand.security.model.SpringSecurityUser;
import com.monkeyhand.security.model.json.AuthenticationRequest;
import com.monkeyhand.security.model.json.AuthenticationResponse;
import com.monkeyhand.security.util.TokenUtils;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private TokenUtils tokenUtils;

	@Autowired
	private UserDetailsService userDetailsService;
	
	public final String tokenHeader = "X-Auth-Token";

	@RequestMapping(method = RequestMethod.POST)
	public ResponseEntity<AuthenticationResponse> authenticationRequest(@RequestBody AuthenticationRequest authenticationRequest) throws AuthenticationException {
		Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
		String token = tokenUtils.generateToken(userDetails);
		return new ResponseEntity<AuthenticationResponse>(new AuthenticationResponse(token), HttpStatus.OK);
	}

	@RequestMapping(value = "refresh", method = RequestMethod.GET)
	public ResponseEntity<AuthenticationResponse> authenticationRequest(HttpServletRequest request) {
		String token = request.getHeader(tokenHeader);
		String username = this.tokenUtils.getUserNameFromToken(token);
		SpringSecurityUser user = (SpringSecurityUser) this.userDetailsService.loadUserByUsername(username);
		if (this.tokenUtils.canTokenBeRefreshed(token, user.getLastPasswordReset())) {
			String refreshedToken = this.tokenUtils.refreshToken(token);
			return new ResponseEntity<AuthenticationResponse>(new AuthenticationResponse(refreshedToken), HttpStatus.OK);
		} else {
			return ResponseEntity.badRequest().body(null);
		}
	}
}
