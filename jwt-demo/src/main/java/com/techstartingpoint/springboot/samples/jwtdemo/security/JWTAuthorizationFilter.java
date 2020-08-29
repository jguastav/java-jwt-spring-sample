package com.techstartingpoint.springboot.samples.jwtdemo.security;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

	
	private final String HEADER = "Authorization";
	private final String PREFIX = "Bearer ";
	
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			if (existsJWTToken(request, response)) {
				Claims claims = validateToken(request);
				if (claims.get("authorities") != null) {
					setUpSpringAuthentication(claims);
				} else {
					SecurityContextHolder.clearContext();
				}
			} else {
					SecurityContextHolder.clearContext();
			}
			filterChain.doFilter(request, response);
		} catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException | NoSuchAlgorithmException | InvalidKeySpecException e)  {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
			return;
		}		
	}
	
	
	/**
	 * Get Algorithm from alg definition in header
	 * 
	 * @param jwtToken
	 * 	e.g. {"alg":"HS512"}
	 * @return
	 */
	private String getAlgorithm(String jwtToken) {
		String result = null;
		int pos = jwtToken.indexOf(".");
		if (pos>0) {
			String jwtTokenDecoded =  new String(Base64.getDecoder().decode(jwtToken.substring(0,pos)));
			result = jwtTokenDecoded.substring(8,jwtTokenDecoded.length()-2);
		}
		return result;		
	}
	
	
	
	private Claims validateToken(HttpServletRequest request) throws SignatureException, NoSuchAlgorithmException, InvalidKeySpecException {
		// TODO: Check if this only works when only Bearer Header is sent
		// TODO: Check if it is expired
		Claims result = null;
		String jwtToken = request.getHeader(HEADER).replace(PREFIX, "");

		
			
			JwtParser parser = Jwts.parser();
			// determine algorithm as it is specified on header
			String algorithm = getAlgorithm(jwtToken);
			JwtParser signedParser=null;
			if (algorithm != null) {
				switch (algorithm) {
				case "HS512": 
					signedParser = parser.setSigningKey(SamplePrivatePublicKeys.UNIQUE_SECRET_KEY.getBytes());
					System.out.println("Signed with secret key");
					break;
				case "RS256": 
					PublicKey publicKey = PublicPrivateRSAKeyGenerator.getPublicKeyFromBase64String(SamplePrivatePublicKeys.PUBLIC_KEY);
					signedParser = parser.setSigningKey(publicKey);
					System.out.println("Signed with public key");
					break;
				}
				if (signedParser != null) {
					Jws<Claims> jwsClaims=signedParser.parseClaimsJws(jwtToken);
					result = jwsClaims.getBody();
//					jwsClaims.getHeader().getAlgorithm();
				}
				
			}
			
			return result;
		
		
	}	
	
	private boolean existsJWTToken(HttpServletRequest request, HttpServletResponse res) {
		String authenticationHeader = request.getHeader(HEADER);
		if (authenticationHeader == null || !authenticationHeader.startsWith(PREFIX))
			return false;
		return true;
	}	
	
	
	/**
	 * Metodo para autenticarnos dentro del flujo de Spring
	 * 
	 * @param claims
	 */
	private void setUpSpringAuthentication(Claims claims) {
//		@SuppressWarnings("unchecked")
		List<String> authorities = (List) claims.get("authorities");

		UsernamePasswordAuthenticationToken auth = 
				new UsernamePasswordAuthenticationToken(claims.getSubject(), null,authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
		SecurityContextHolder.getContext().setAuthentication(auth);

	}	
	

}
