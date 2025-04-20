package com.blog.security;



import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenHelper {
	
	public static final long JWT_TOKEN_VALIDITY=5*60*60;
	
	private String secret="5e3a7b134f9d4960b8f4434ad478e314e1b0a3c5a2ddfe2f3e13c24ab9f49df33be347b2bc22fd43435c0c6b77e738e79e6ea37b772ccf1c5093b03ac0bfb917";

	
	//retrieve username from jwt token
	public String getUsernameFromToken(String token)
	{
		return getClaimFromToken(token,Claims::getSubject);
	}
	
	//retrive expiration date from jwt token
	public Date getExpirationDateFromToken(String token)
	{
		return getClaimFromToken(token,Claims::getExpiration);
	}
	
	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver)
	{
		final Claims claims= getAllClaimsFromToken(token);
	    return claimsResolver.apply(claims);
	}
	
//	private Key getSigningKey() {
//	    byte[] keyBytes = Base64.getDecoder().decode(secret);
//	    return new SecretKeySpec(keyBytes, 0, keyBytes.length, "HmacSHA512");
//	}
	// Generating a 64-byte secret key properly
//	private String secret = "5e3a7b134f9d4960b8f4434ad478e314e1b0a3c5a2ddfe2f3e13c24ab9f49df33be347b2bc22fd43435c0c6b77e738e79e6ea37b772ccf1c5093b03ac0bfb917"; // 64 bytes hex

	// Ensure you're not Base64 encoding or decoding if the string is already of sufficient length
	private Key getSigningKey() {
	    byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8); // Should be 64 bytes for HS512
	    return new SecretKeySpec(keyBytes, SignatureAlgorithm.HS512.getJcaName());
	}

	//for retrieving any information from token we will need the secret key
//	private Claims getAllClaimsFromToken(String token)
//	{
//		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
//	}
	private Claims getAllClaimsFromToken(String token) {
	    return Jwts
	            .parserBuilder()
	            .setSigningKey(getSigningKey()) // use a Key object, not String
	            .build()
	            .parseClaimsJws(token)
	            .getBody();
	}
	
	//check if the token has expired
	private Boolean isTokenExpired(String token)
	{
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}
	
	//generate toekn for user
	public String generateToken(UserDetails userDetails)
	{
		Map<String, Object> claims= new HashMap<>();
        return doGenerateToken(claims,userDetails.getUsername());
	}
	
	// While creating the token:
	// 1. Define claims of the token, like issuer, expiration, subject, and the ID.
	// 2. Sign the JWT using the HS512 algorithm and a secret key.
	// 3. According to JWS Compact Serialization (https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41),
    //	    compact the JWT to a URL-safe string.

//	private String doGenerateToken(Map<String, Object> claims, String subject) {
//	    return Jwts.builder()
//	        .setClaims(claims)
//	        .setSubject(subject)
//	        .setIssuedAt(new Date(System.currentTimeMillis()))
//	        .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000)) // JWT_TOKEN_VALIDITY in seconds
//	        .signWith(SignatureAlgorithm.HS512, secret)
//	        .compact();
//	}
	
	private String doGenerateToken(Map<String, Object> claims, String subject) {
	    Key signingKey = getSigningKey(); // Get the signing key using the method you added

	    return Jwts.builder()
	        .setClaims(claims)
	        .setSubject(subject)
	        .setIssuedAt(new Date(System.currentTimeMillis()))
	        .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000)) // JWT_TOKEN_VALIDITY in seconds
	        .signWith(signingKey, SignatureAlgorithm.HS512) // Use signingKey instead of secret
	        .compact();
	}

	
	//validate token
	public Boolean validateToken(String token, UserDetails userDetails)
	{
		final String username=getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
}
