# JWT How to in Java with Spring with Public and Private Key and with Secret Key (2 Scenarios)
See the concepts in 
https://www.techstartingpoint.com/es/que-es-jwt-para-que-sirve-y-como-funciona/


# Read Me First



The following was discovered as part of building this project:

* The original package name 'com.techstartingpoint.springboot.samples.jwt-demo' is invalid and this project uses 'com.techstartingpoint.springboot.samples.jwtdemo' instead.

# Getting Started

### Reference Documentation
For further reference, please consider the following sections:

* [Official Gradle documentation](https://docs.gradle.org)
* [Spring Boot Gradle Plugin Reference Guide](https://docs.spring.io/spring-boot/docs/2.3.3.RELEASE/gradle-plugin/reference/html/)
* [Create an OCI image](https://docs.spring.io/spring-boot/docs/2.3.3.RELEASE/gradle-plugin/reference/html/#build-image)
* [Spring Web](https://docs.spring.io/spring-boot/docs/2.3.3.RELEASE/reference/htmlsingle/#boot-features-developing-web-applications)
* [Spring Security](https://docs.spring.io/spring-boot/docs/2.3.3.RELEASE/reference/htmlsingle/#boot-features-security)

### Guides
The following guides illustrate how to use some features concretely:

* [Building a RESTful Web Service](https://spring.io/guides/gs/rest-service/)
* [Serving Web Content with Spring MVC](https://spring.io/guides/gs/serving-web-content/)
* [Building REST services with Spring](https://spring.io/guides/tutorials/bookmarks/)
* [Securing a Web Application](https://spring.io/guides/gs/securing-web/)
* [Spring Boot and OAuth2](https://spring.io/guides/tutorials/spring-boot-oauth2/)
* [Authenticating a User with LDAP](https://spring.io/guides/gs/authenticating-ldap/)

### Additional Links
These additional references should also help you:

* [Gradle Build Scans – insights for your project's build](https://scans.gradle.com#gradle)


### Dependencies
This project was created with start.spring.io with the following Dependencies
Spring Security
Spring Web

### Reference
https://github.com/sebascastillo89/jwtDemo
https://blog.softtek.com/es/autenticando-apis-con-spring-y-jwt
https://jwt.io/introduction/
https://github.com/lokeshgupta1981/spring-webmvc
https://howtodoinjava.com/spring5/webmvc/spring5-mvc-hibernate5-example/
https://dzone.com/articles/spring-boot-2-with-jsp-view
https://github.com/lokeshgupta1981/spring-webmvc
In this example is also shown how to do it with pair private and public key
https://github.com/jwtk/jjwt#jws-key-create-secret
https://en.wikipedia.org/wiki/Cross-site_request_forgery
csrf.disable() in main app class

Create jwt in java using Public key rsa	
https://wstutorial.com/misc/jwt-java-public-key-rsa.html

Serialize private and public keys
https://www.novixys.com/blog/how-to-generate-rsa-keys-java/

JSON Web Tokens with Public Key Signatures
https://blog.miguelgrinberg.com/post/json-web-tokens-with-public-key-signatures

Tutorial: Create and Verify JWTs in Java
https://developer.okta.com/blog/2018/10/31/jwts-with-java


https://wstutorial.com/misc/jwt-java-public-key-rsa.html


# Run and check the application

The application identifies a user in 2 scenarios using JWT:
1.- Scenario using SECRET_KEY to encrypt (sign) and decrypt the token. This is generally the common scenario for a web service architecture where the provider of the services is the same who provides the identifier service.
2.- Scenario using PRIVATE_KEY to encrypt (sign) and PUBLIC_KEY to decrypt the token. This is generally the common scenario when the issuer of the identifier service is not the same of the services and resources that are obtainded later. 

The SECRET_KEY of scenario 1 and the PRIVATE_KEY and PUBLIC_KEY for scenario 2 are available in class SamplePrivatePublicKeys.java
These keys must be changed on a production environment in your own scenario. 
The SECRET_KEY can be generated manually.
Each time the application runs is generated a new pair or PRIVATE_KEY and PUBLIC_KEY in the logs of the app, in case you want a new pair of public and private keys. 
But you don't need to use those. It's only a service to show how they are generated. 
The public and private keys shown in the log are encoded in base64.

Run as Java application : class JwtDemoApplication.java
In the log it is shown a new generated PrivateKey and PublicKey.
You can use those values to change the pair of keys in the class SamplePrivatePublicKeys but you can also decide leave them without changing.


When the app is running you can check:

curl -X GET localhost:8080/hello

An error 403 should be received because the user is not authenticated. 


#### Scenario 1

Then run 
curl -X POST localhost:8080/user -d user=jose -d password=password1

The response should be similar to this:
{"user":"jose","password":"password1","token":"Bearer eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiJpZE9mVGhlSWRlbnRpZmllckF1dGhvcml0eVdob1NpZ25zVGhlVG9rZW5BbmRJc1RydXN0ZWRCeVRoZVJlc291cmNlQW5kQXV0aGVudGljYXRpb25TZXJ2ZXIiLCJzdWIiOiJqb3NlIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImlhdCI6MTU5ODQ4NjE4MSwiZXhwIjoxNTk4NDg2NzgxfQ.aW1DJx0RI8_tfHRefxIrx306Gx_cq_--lbaTPCxNDience4amVz-lQ3eBN7ZxwDiqpsPYTdITlSBcc387_RONg"}


Then, getting the value of the token run 
curl -X GET localhost:8080/hello -H "Bearer eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiJpZE9mVGhlSWRlbnRpZmllckF1dGhvcml0eVdob1NpZ25zVGhlVG9rZW5BbmRJc1RydXN0ZWRCeVRoZVJlc291cmNlQW5kQXV0aGVudGljYXRpb25TZXJ2ZXIiLCJzdWIiOiJqb3NlIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImlhdCI6MTU5ODQ4NjE4MSwiZXhwIjoxNTk4NDg2NzgxfQ.aW1DJx0RI8_tfHRefxIrx306Gx_cq_--lbaTPCxNDience4amVz-lQ3eBN7ZxwDiqpsPYTdITlSBcc387_RONg"

The response should be 
Hello World! 


as the user was validated with the token.

In the log should be printed:
Signed with secret key

As the decrypt of the token was made with the SECRET_KEY (as stated for scenario 1).This is the same SECRET_KEY used to sign (encrypt) the JWT Token.

#### Scenario 2
This is the common scenario when the issuer of the JWT token is different of the provider of the rest of the services. 

Ask for 3rd party private public authentication

curl -X POST localhost:8080/userOnExternalJWTIssuer -d user=jose -d password=password1

The response will be similar to: 

{"user":"jose","password":null,"token":"Bearer eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJpZE9mVGhlSWRlbnRpZmllckF1dGhvcml0eVdob1NpZ25zVGhlVG9rZW5BbmRJc1RydXN0ZWRCeVRoZVJlc291cmNlQW5kQXV0aGVudGljYXRpb25TZXJ2ZXIiLCJpc3MiOiJmYWtlQHRlY2hzdGFydGlucG9pbnQuY29tIiwic3ViIjoiam9zZSIsImF1dGhvcml0aWVzIjpbIlJPTEVfVVNFUiJdLCJpYXQiOjE1OTg1NDM4NjYsImV4cCI6MTU5ODU0NDQ2Nn0.pHo9Ug04KDAccwnypVlICuiUL2e5iY23fQWxrJPfyWcGAWUF2w-CIjv7FwtxItAvJg2-9yreW7RSAgsEoTYw7eOXMc2zXUEuIDG5f21CWuiVxbgX3C0sbeI2H_PHv7grqT8t_Ia4kwAsKMHxMBYQn51k8J91mKf49Y1f04N7524Nxt8Qi9M8hc9U1mN8EIacuLt-E2CQQJe-vAHBxYD_tATLCWRLnZdAYLpi_OHggTZjPQ4W5Sdr2gy1ecmH1ZpTSkTMFGvhcBOerrnA9RvuZrrz2B81CDLTjM6WnjZA8aiK-Pq_54C-wapLYKCrauOBl__wyr17uymJrbnDPm7iFg"}


Then copy the token to the Authorization header property value

e.g. 
curl -X GET localhost:8080/hello -H "Authorization:Bearer eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJpZE9mVGhlSWRlbnRpZmllckF1dGhvcml0eVdob1NpZ25zVGhlVG9rZW5BbmRJc1RydXN0ZWRCeVRoZVJlc291cmNlQW5kQXV0aGVudGljYXRpb25TZXJ2ZXIiLCJpc3MiOiJmYWtlQHRlY2hzdGFydGlucG9pbnQuY29tIiwic3ViIjoiam9zZSIsImF1dGhvcml0aWVzIjpbIlJPTEVfVVNFUiJdLCJpYXQiOjE1OTg1NDM4NjYsImV4cCI6MTU5ODU0NDQ2Nn0.pHo9Ug04KDAccwnypVlICuiUL2e5iY23fQWxrJPfyWcGAWUF2w-CIjv7FwtxItAvJg2-9yreW7RSAgsEoTYw7eOXMc2zXUEuIDG5f21CWuiVxbgX3C0sbeI2H_PHv7grqT8t_Ia4kwAsKMHxMBYQn51k8J91mKf49Y1f04N7524Nxt8Qi9M8hc9U1mN8EIacuLt-E2CQQJe-vAHBxYD_tATLCWRLnZdAYLpi_OHggTZjPQ4W5Sdr2gy1ecmH1ZpTSkTMFGvhcBOerrnA9RvuZrrz2B81CDLTjM6WnjZA8aiK-Pq_54C-wapLYKCrauOBl__wyr17uymJrbnDPm7iFg"


And the app should return 
Hello World!!



In the logs is shown :
Signed with public key

As the key to decrpyt the JWT token is the publick key correspondint to the private_key the issuer used to generate the JWT Token


### Using in frontend

The app in frontend is not completely done but there are a few entrypoints to check it in 
Check in http://localhost:8080

and

http://localhost:8080/hello?name=jose

