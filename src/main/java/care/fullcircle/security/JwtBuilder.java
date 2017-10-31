package care.fullcircle.security;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;

/**
 * Created by oleh.kuprovskyi on 05.10.17.
 */
@Component
public class JwtBuilder {

//    @Value("${jwt.header:'telemed'}")
//    private String tokenHeader;

    @Value("${jwt.expiration.time:60}")
    private Integer expiration;

    public String createJWT(String email, String accountId, String role, String clientIP, String browserFingerprintDigest) {

        Date now = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.SECOND, this.expiration);

        String jws = null;
        try {
            jws = Jwts.builder()
                .setIssuer("Telemed")
                .claim("email", email)
                .claim("account_id", accountId)
                .claim("role", role)
                .claim("clientIP", clientIP)
                .claim("browserFingerprintDigest", browserFingerprintDigest)
                .setIssuedAt(now)
                .setExpiration(calendar.getTime())
                .signWith(
                    SignatureAlgorithm.HS256,
                    "telemed".getBytes("UTF-8")
                )
                .compact();
        } catch (Exception e) {

        }

        return jws;
    }
}
