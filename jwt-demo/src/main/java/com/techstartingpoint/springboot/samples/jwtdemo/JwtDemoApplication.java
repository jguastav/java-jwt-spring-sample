package com.techstartingpoint.springboot.samples.jwtdemo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.techstartingpoint.springboot.samples.jwtdemo.security.Base64KeyPair;
import com.techstartingpoint.springboot.samples.jwtdemo.security.JWTAuthorizationFilter;
import com.techstartingpoint.springboot.samples.jwtdemo.security.PublicPrivateRSAKeyGenerator;

@SpringBootApplication
public class JwtDemoApplication {

	
	  private static final Logger log = LoggerFactory.getLogger(JwtDemoApplication.class);	
	
	public static void main(String[] args) {
		SpringApplication.run(JwtDemoApplication.class, args);
	}
	
	
	@EnableWebSecurity
	@Configuration
	class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.csrf().disable()
				.addFilterAfter(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class) //  interceptar las invocaciones a recursos protegidos para recuperar el token y determinar si el cliente tiene permisos o no.
				.authorizeRequests()
				.antMatchers(HttpMethod.POST, "/user").permitAll()
				.antMatchers(HttpMethod.POST, "/userOnExternalJWTIssuer").permitAll()
				.antMatchers(HttpMethod.GET, "/login").permitAll()
				.anyRequest().authenticated();
		}
	}
	
	
	  @Bean
	  public CommandLineRunner printPublicPrivateKeys() {
	    return (args) -> {
	      // save a few customers
	    	
	    	Base64KeyPair keys= PublicPrivateRSAKeyGenerator.getKeyPair();
	    	log.info("Private key:"+keys.getPrivateKey());
	    	log.info("Private key:"+keys.getPrivateKeyFormat());
	    	
	    	log.info("Public key:"+keys.getPublicKey());
	    	log.info("Private key:"+keys.getPublicKeyFormat());
	    	
	    };
	  }	

}
