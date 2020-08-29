package com.techstartingpoint.springboot.samples.jwtdemo.security;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class PublicPrivateRSAKeyGenerator {
	
	final private static String ALGORITHM="RSA"; 
	
	public static Base64KeyPair getKeyPair() throws NoSuchAlgorithmException {
//		https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator		
//		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
		KeyPair pair = keyGen.generateKeyPair();
		PublicKey publicKey = pair.getPublic();
		PrivateKey privateKey = pair.getPrivate();
		
		Base64KeyPair result = 
				new Base64KeyPair( Base64.getEncoder().encodeToString(publicKey.getEncoded()),
						publicKey.getFormat(),
						Base64.getEncoder().encodeToString(privateKey.getEncoded()),
						privateKey.getFormat());
		return result;
	}
	
	
	public static PrivateKey getPrivateKeyFromBase64String(String base64PrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		/* Generate private key. */
		PKCS8EncodedKeySpec keySpecification = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpecification);
		return privateKey;
	}
	
	
	public static PublicKey getPublicKeyFromBase64String(String base64PublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		/* Generate public key. */
		X509EncodedKeySpec encodedKey = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(encodedKey);		
		return publicKey;
	}
}
