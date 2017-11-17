package care.fullcircle.security;

import care.fullcircle.dto.security.JwtUserDetails;
import care.fullcircle.util.ClientIp;
import care.fullcircle.util.SessionUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
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

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    private final String[] localIPs = {"0:0:0:0:0:0:0:1","127.0.0.1", "192.168.1.1", "192.168.0.1"};
//    @Resource
//    SecurityDaoImpl dao;
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
        } catch (SignatureException e) {
            LOGGER.error("token validation failed with key " + jwtKey);
        } catch (ExpiredJwtException eje) {
            LOGGER.debug("Token is expired - but valid");
            valid = true;
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

            if (Arrays.asList(localIPs).contains(clientIp)) {
                return true;
            }

            if (clientIp.equals(ip)) {
                valid = true;
            } else {
                LOGGER.info("SecurityServiceImpl.checkClientIp: Not valid clientIp");
                LOGGER.info("jwtIp: " + ip);
                LOGGER.info("clientIP: " + clientIp);
                LOGGER.debug("ClientIp is not the same as requested");
            }
        } catch (SignatureException e) {
            LOGGER.error("token validation failed with key " + jwtKey);
        }

        return (valid);
    }

    //=======================
    public boolean checkSessionId(HttpServletRequest httpServletRequest, String token) {
        boolean valid = false;

        try {
            Claims claims = Jwts.parser().setSigningKey(getJwtKey()).parseClaimsJws(token).getBody();
            String sessionId = (String)claims.get("sessionId");
            LOGGER.info("sessionId: " + sessionId);

            if (SessionUtil.getSession(httpServletRequest, true).getId().equals(sessionId)) {
                valid = true;
            } else {
                LOGGER.debug("SessionID is not valid");
            }

            if (null != httpServletRequest.getRequestedSessionId() &&
                    !SessionUtil.getSession(httpServletRequest, true).getId().equals(httpServletRequest.getRequestedSessionId())) {
//                valid = true;
//            } else {
                valid = false;
                LOGGER.debug("SessionID is not the same as requested");
            }

        } catch (SignatureException e) {
            LOGGER.error("token validation failed with key " + jwtKey);
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
        }

        return (expired);
    }

//
//    //=======================
//    public boolean isSessionIdValid(String authToken) {
//        boolean valid = true;
//
//        try {
//            //TODO extract and check
//            valid = false;
//        } catch (ExpiredJwtException eje) {
//            System.out.println("SessionId is not valid " );
//        }
//
//        return valid;
//    }
//
//
//    //=======================
//    public boolean isClientIpValid(String authToken) {
//        boolean valid = true;
//
//        try {
//            //TODO extract and check
//            //TODO check getRequestedSessionId and currentSessionId
//            valid = false;
//        } catch (ExpiredJwtException eje) {
//            System.out.println("ClientIP is not valid " );
//        }
//
//        return valid;
//    }


    //=======================
    public UserDetails getUserByToken(String token) {
        // get user roles
        Claims claims = Jwts.parser().setSigningKey(getJwtKey()).parseClaimsJws(token).getBody();
        //TODO
        Object role = claims.get("role");
        ArrayList<String> tmp = new ArrayList<String>();
        tmp.add(role.toString());
//            tmp = (ArrayList<String>)claims.get("roles");
//        ArrayList<String> tmp = (ArrayList<String>)claims.get("roles");
        // convert string roles to actual security roles
        ArrayList<GrantedAuthority> roles = new ArrayList<>();
        for (String roleName : tmp) {
            GrantedAuthority auth = new SimpleGrantedAuthority(roleName);
            roles.add(auth);
        }

//        Long idl = 0L;

//        Object id = claims.get("id");
//        if (id instanceof String) {
//           idl = new Long(Long.parseLong((String)id));
//        } else if (id instanceof Integer) {
//           idl =  Long.valueOf(((Integer)id).longValue());
//        }

//        log.debug("id as long is " + idl);
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

    //=======================
//    public UserDetails getUserFromDB(String token) {
//
//        JwtUserDetails user = null;
//
//        if (token != null && !token.isEmpty()) {
//            JwtUserDetails temp = (JwtUserDetails)dao.getTokenRoles(token);
//            Date currentDate = new Date(System.currentTimeMillis());
//            log.info("Validating token expiration, got " + temp.getTokenExpirationDate() + " and now it is " + currentDate);
//
//            // check that this is valid
//            if(temp.getTokenExpirationDate().after(currentDate)) {
//               user = temp;
//            }
//        }
//
//        return (user);
//    }

    private byte[] getJwtKey() {
        return jwtKey.getBytes();
    }

}
