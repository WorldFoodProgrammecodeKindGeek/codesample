package com.kindgeek.security;

import care.fullcircle.dto.security.JwtUserDetails;
import care.fullcircle.util.ClientIp;
import care.fullcircle.util.SessionUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

@Service
public class SecurityServiceImpl implements SecurityService {

    private final Logger LOG = LoggerFactory.getLogger(this.getClass());

    private final String[] localIPs = {"0:0:0:0:0:0:0:1","127.0.0.1", "192.168.1.1", "192.168.0.1"};

    @Value("${jwt.key}")
    private String jwtKey;

    // HMAC key - Block serialization and storage as String in JVM memory
    private transient byte[] keyHMAC = null;

    //=======================
    public boolean isTokenValid(String token) {
        boolean valid = false;

        try {
            Jwts.parser().setSigningKey(getJwtKey()).parseClaimsJws(token);
            valid = true;
        } catch (ExpiredJwtException eje) {
            LOG.error("Token is expired - but valid");
            valid = true;
        } catch (MalformedJwtException exep) {
            LOG.error("token validation failed");
        } catch (Exception exep) {
            LOG.error("token validation failed");
        }

        return (valid);
    }

    //=======================
    public boolean checkClientIp(HttpServletRequest httpServletRequest, String token) {
        boolean valid = false;

        try {
            Claims claims = Jwts.parser().setSigningKey(getJwtKey()).parseClaimsJws(token).getBody();
            String ip = (String)claims.get("clientIP");
            String clientIp = ClientIp.retrieveClientIP(httpServletRequest);

            // Allow access from local IP addresses
            if (Arrays.asList(localIPs).contains(clientIp)) {
                return true;
            }

            if (clientIp.equals(ip)) {
                valid = true;
            } else {
                LOG.debug("ClientIp is not the same as requested");
            }
        } catch (MalformedJwtException exep) {
            LOG.error("token validation failed");
        } catch (Exception exep) {
            LOG.error("token validation failed");
        }

        return (valid);
    }

    //=======================
    public boolean checkSessionId(HttpServletRequest httpServletRequest, String token) {
        boolean valid = false;

        try {
            Claims claims = Jwts.parser().setSigningKey(getJwtKey()).parseClaimsJws(token).getBody();
            String sessionId = (String)claims.get("sessionId");
            LOG.info("sessionId: " + sessionId);

            if (SessionUtil.getSession(httpServletRequest, true).getId().equals(sessionId)) {
                valid = true;
            } else {
                LOG.debug("SessionID is not valid");
            }

            if (null != httpServletRequest.getRequestedSessionId() &&
                    !SessionUtil.getSession(httpServletRequest, true).getId().equals(httpServletRequest.getRequestedSessionId())) {
                valid = false;
                LOG.debug("SessionID is not the same as requested");
            }
        } catch (MalformedJwtException exep) {
            LOG.error("token validation failed");
        } catch (Exception exep) {
            LOG.error("token validation failed");
        }

        return (valid);
    }


    //=======================
    public boolean isTokenExpired(String authToken) {
        boolean expired = true;

        try {
            Date date = Jwts.parser().setSigningKey(getJwtKey()).parseClaimsJws(authToken).getBody().getExpiration();
            expired = false;
        } catch (ExpiredJwtException eje) {
            System.out.println("Token is expired " );
        } catch (MalformedJwtException exep) {
            LOG.error("token validation failed");
        } catch (Exception exep) {
            LOG.error("token validation failed");
        }

        return (expired);
    }

    //=======================
    public UserDetails getUserByToken(String token) {
        // get user roles
        Claims claims = Jwts.parser().setSigningKey(getJwtKey()).parseClaimsJws(token).getBody();

        Object role = claims.get("role");
        ArrayList<String> tmp = new ArrayList<String>();
        tmp.add(role.toString());

        // convert string roles to actual security roles
        ArrayList<GrantedAuthority> roles = new ArrayList<>();
        for (String roleName : tmp) {
            GrantedAuthority auth = new SimpleGrantedAuthority(roleName);
            roles.add(auth);
        }

        String email = (String)claims.get("email");
        Object id =  claims.get("account_id");
        String ip = (String)claims.get("clientIP");
        String sessionId = (String)claims.get("sessionId");
        String fingerprint = (String)claims.get("browserFingerprintDigest");
        Long accountId = 0L;
        if (id instanceof String) {
            accountId = new Long(Long.parseLong((String)id));
        } else if (id instanceof Integer) {
            accountId =  Long.valueOf(((Integer)id).longValue());
        }

        // create the user credentials object
        JwtUserDetails userDetails = new JwtUserDetails(accountId, email, roles, true, ip, sessionId, fingerprint);
        userDetails.setUserToken(token);
        return (userDetails);
    }

    private byte[] getJwtKey() {
        return jwtKey.getBytes();
    }

}
