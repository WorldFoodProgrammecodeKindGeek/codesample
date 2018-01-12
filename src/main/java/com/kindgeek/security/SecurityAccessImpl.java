package com.kindgeek.security;

import org.apache.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author Oleh Kuprovskyi <oleh.kuprovskyi@kindgeek.com>
 */
@Service
public class SecurityAccessImpl implements SecurityAccess {
    private static final Logger LOG = Logger.getLogger(SecurityAccessImpl.class);


    private List<? extends GrantedAuthority> getRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null || !authentication.isAuthenticated()){
            return null;
        }

        return (List<? extends GrantedAuthority>) authentication.getAuthorities();
    }

    @Override
    public boolean denyAccessUnlessGranted(Collection<String> roles) {
        boolean authenticated = false;
        List<? extends GrantedAuthority> authorities =  getRoles();
        List<String> rolesList = new ArrayList<>();
        for (int i = 0;i<authorities.size();i++) {
            rolesList.add(authorities.get(i).getAuthority());
        }

        for(String role : roles){
            if(rolesList.contains(role)){
                authenticated = true;
                break;
            }
        }

        return authenticated;
    }
}
