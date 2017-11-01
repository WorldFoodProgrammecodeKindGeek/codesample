package care.fullcircle.security;

import org.springframework.security.core.userdetails.UserDetails;

public interface SecurityService {

    boolean isTokenValid(String token);

    boolean isTokenExpired(String authToken);

    UserDetails getUserByToken(String token);
}
