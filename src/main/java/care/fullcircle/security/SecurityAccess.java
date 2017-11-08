package care.fullcircle.security;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

/**
 * Created by yaromyryaremko on 08.11.17.
 */
public interface SecurityAccess {
    boolean denyAccessUnlessGranted(Collection<String> roles);
}
