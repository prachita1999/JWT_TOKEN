package com.example.librerymanegement.JWT;


import java.sql.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
	
	@Value("${jwt.secretkey}")
	private String secretkey;
	
	@Value("${jwt.expiration}")
	private Long jwtExpiration;
	
	public String extractUsername(String jwtToken) {
		return extractClaim(jwtToken,Claims:: getSubjec);
		
	}
	private <T> T exctractClaim(String jwtToken, Function<Claims, T> claimResolver) {
		final Claims claims = extractAllClaims(jwtToken);
		
		return claimResolver.apply(claims);
	}
	
	private Claims extractAllClaims(String jwtToken) {
		
		return Jwts
				.parser()
				.verifywith(getSignInKey())
				.build()
				.parseSignedClaims(jwtToken)
				.getPayLoad();
	}  
	
	public SecretKey getSignInKey() {
		
		return Keys.hmacShakeyFor(secretkey.getBytes());
	}
	
	public String generateToken(UserDetails userDetails) {
		
		return generateToken(new HashMap<>(),userDetails);
		
	}
	
	public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails) {
		return Jwts
				.builder()
				.Claims(extraClaims)
				.subject(userDetails.getUsername())
				.issueAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis()+ jwtExpiration))
				.SignWith(getSignInKey())
				.compact();
	}
	
	public boolean isTokenValid(String jwtToken,UserDetails userDetails) {
		
		final String  usrname = extractUsername(jwtToken);
		
		return (userDetails.getUsername().equals(usrname)&&!isTokenExpired(jwtToken));
				
	}
	private boolean isTokenExpired(String jwtToken) {
	
		return extractExpiration(jwtToken).before(new Date());
	}
	private Date extractExpiration(String jwtToken) {
		return extractClaim(jwtToken,Claims:: getExpiration);
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
