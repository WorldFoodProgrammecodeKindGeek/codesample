package care.fullcircle.security;

import org.springframework.security.core.userdetails.UserDetails;


public interface SecurityService {


    public boolean isTokenValid(String token);

    public boolean isTokenExpired(String authToken);

    public UserDetails getUserByToken(String token);
}
