package care.fullcircle.security;

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

import java.util.ArrayList;
import java.util.Date;

@Service
public class SecurityServiceImpl implements SecurityService {

    private final Logger log = LoggerFactory.getLogger(this.getClass());
//    @Resource
//    SecurityDaoImpl dao;
    @Value("${jwt.key}")
    private String jwtKey;

    //=======================
    public boolean isTokenValid(String token) {
        boolean valid = false;

        try {
            Jwts.parser().setSigningKey(getJwtKey()).parseClaimsJws(token);
            valid = true;
        } catch (SignatureException e) {
            log.error("token validation failed with key " + jwtKey);
        } catch (ExpiredJwtException eje) {
            log.debug("Token is expired - but valid");
            valid = true;
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
        Long accountId = 0L;
        if (id instanceof String) {
            accountId = new Long(Long.parseLong((String)id));
        } else if (id instanceof Integer) {
            accountId =  Long.valueOf(((Integer)id).longValue());
        }


        // create the user credentials object
        JwtUserDetails userDetails = new JwtUserDetails(accountId, email, roles,true, new Date());
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
