package care.fullcircle.security;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;

import java.util.Calendar;
import java.util.Date;

/**
 * Created by oleh.kuprovskyi on 05.10.17.
 */
public class JwtBuilder {

    @Value("${jwt.header:'telemed'}")
    private String tokenHeader;

    public String createJWT(String email, String accountId, String role) {

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.HOUR, 1);

        String jws = null;

        try {
            jws = Jwts.builder()
                .setIssuer("Telemed")
                .claim("email", email)
                .claim("account_id", accountId)
                .claim("role", role)
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
