package com.techstartingpoint.springboot.samples.jwtdemo.security;

public class Base64KeyPair {

		String publicKey;
		String privateKey;
		
		String publicKeyFormat;
		String privateKeyFormat;
		
		
		
		public Base64KeyPair(String publicKey, String publicKeyFormat,String privateKey,String privateKeyFormat) {
			super();
			this.publicKey = publicKey;
			this.publicKeyFormat = publicKeyFormat;
			this.privateKey = privateKey;
			this.privateKeyFormat = privateKeyFormat;
		}
		
		public String getPublicKey() {
			return publicKey;
		}
		public void setPublicKey(String publicKey) {
			this.publicKey = publicKey;
		}
		public String getPrivateKey() {
			return privateKey;
		}
		public void setPrivateKey(String privateKey) {
			this.privateKey = privateKey;
		}

		public String getPublicKeyFormat() {
			return publicKeyFormat;
		}

		public void setPublicKeyFormat(String publicKeyFormat) {
			this.publicKeyFormat = publicKeyFormat;
		}

		public String getPrivateKeyFormat() {
			return privateKeyFormat;
		}

		public void setPrivateKeyFormat(String privateKeyFormat) {
			this.privateKeyFormat = privateKeyFormat;
		}
		
		
		
		
}
