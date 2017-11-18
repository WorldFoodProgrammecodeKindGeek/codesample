Telemed Boot Security!
===================

> **Resources:**
> 
> - http://www.baeldung.com/java-json-web-tokens-jjwt
> - https://jwt.io/ JWT online debugger
> - http://jwtbuilder.jamiekurtz.com/

### Integration

Steps to add boot_security to telemed services:

1. Build boot_security.jar (https://bitbucket.org/kindgeek-platform/boot-security)
2. In your application add dependencies to .pom file
```
<!-- Spring-boot-security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>care.fullcircle</groupId>
    <artifactId>boot_security</artifactId>
    <version>1.0</version>
</dependency>
```

3. Add 'SecuredApplication' extension to your Application
```
public class AccountApplication extends SecuredApplication {}
```

4. Add list of annotations
```
@Configuration
@ComponentScan(basePackages = {"care.fullcircle"})
```

5. Add list of required properties to application.properties file
```
# Security configuration
jwt.key=telemed
jwt.header=Authorization
jwt.uri.param=accessToken
jwt.token.admin=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZWxlbWVkIiwiaWF0IjoxNTA3Mjk1MjQ4LCJleHAiOjE1Mzg4MzEyNDgsImF1ZCI6IiIsInN1YiI6IiIsInVzZXJuYW1lIjoiQWRtaW4iLCJhY2NvdW50X2lkIjoiMSIsInJvbGUiOiJST0xFX0FETUlOIn0.4Nt-sxkWiaY5WawxFsYNAqZjv-4O8Chtu-uTWer8Et0

secured.url.pattern=/account/*
external.url.pattern=/account/test

endpoints.enabled=false
endpoints.info.enabled=false

access.control.allow.origin:*
```
