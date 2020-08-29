package com.techstartingpoint.springboot.samples.jwtdemo.security;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTTokenFactory {

	public static String getJWTToken(String username) {
		String token = getJwtBuilder(username)
				.signWith(SignatureAlgorithm.HS512,
						SamplePrivatePublicKeys.UNIQUE_SECRET_KEY.getBytes()).compact();
		
		
		return "Bearer " + token;
	}
	
	
	public static String getJWTTokenThirdPartySchema(String username) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PrivateKey privateKey = PublicPrivateRSAKeyGenerator.getPrivateKeyFromBase64String(SamplePrivatePublicKeys.PRIVATE_KEY);
		
		String token = getJwtBuilder(username)
				.signWith(SignatureAlgorithm.RS256, privateKey).compact();
		return "Bearer " + token;
		
	}	
	
	
	private static JwtBuilder getJwtBuilder(String username) {
		// Esta es la lista de todos los roles que tienen que ver con el permiso
		List<GrantedAuthority> grantedAuthorities = AuthorityUtils
				.commaSeparatedStringToAuthorityList("ROLE_USER");

		/*
		 * Utilizamos el método getJWTToken(...) para construir el token, delegando en la clase de utilidad Jwts que incluye información sobre su expiración y un objeto de GrantedAuthority de Spring que, como veremos más adelante, usaremos para autorizar las peticiones a los recursos protegidos. 
		 */
		JwtBuilder jwtBuilder = Jwts
				.builder()
				.setId("idOfTheIdentifierAuthorityWhoSignsTheTokenAndIsTrustedByTheResourceAndAuthenticationServer")
				.setIssuer("fake@techstartinpoint.com")
				.setSubject(username)
				.claim("authorities",
						grantedAuthorities.stream()
								.map(GrantedAuthority::getAuthority)
								.collect(Collectors.toList()))
				.setIssuedAt(new Date(System.currentTimeMillis()))   // iat part of payload
				.setExpiration(new Date(System.currentTimeMillis() + 600000)) ;// 
		return jwtBuilder;
	}
	
}
