package com.springbootproject.jwt.jwtProject;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.springbootproject.jwt.jwtProject.models.AuthenticationRequest;
import com.springbootproject.jwt.jwtProject.models.AuthenticationResponse;
import com.springbootproject.jwt.jwtProject.util.JwtUtil;

import io.jsonwebtoken.impl.DefaultClaims;

@RestController
public class HelloResource {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JwtUtil jwtUtil;
	
	@RequestMapping(value="/hello", method = RequestMethod.GET)
	public String hello() {
		return "Hello World";
	}
	
	@RequestMapping(value="/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
		}catch(BadCredentialsException e) {
			throw new  Exception("Incorrect Username Password", e);
		}
		
		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
		
		final String jwtToken = jwtUtil.generateToken(userDetails);
		
		return ResponseEntity.ok(new AuthenticationResponse(jwtToken));
	}
	
	@RequestMapping(value="/refreshtoken", method = RequestMethod.GET)
	public ResponseEntity<?> refreshToken( HttpServletRequest request) throws Exception{
		
		DefaultClaims claims = (DefaultClaims) request.getAttribute("claims");
		
		Map<String, Object> expectedMap = getMapFromJsonWebTokenClaims(claims);
		String jwtToken = jwtUtil.generateRefereshToken(expectedMap, expectedMap.get("sub").toString());
		
		return ResponseEntity.ok(new AuthenticationResponse(jwtToken));
	}

	private Map<String, Object> getMapFromJsonWebTokenClaims(DefaultClaims claims) {
		// TODO Auto-generated method stub
		Map<String, Object> expectedMap = new HashMap<String, Object>();
		for(Entry<String, Object> entry : claims.entrySet()) {
			expectedMap.put(entry.getKey(), entry.getValue());
		}
		return expectedMap;
	}
	
	
}
