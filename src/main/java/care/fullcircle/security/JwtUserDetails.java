package care.fullcircle.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Date;

public class JwtUserDetails implements UserDetails {


    private final Long accountId;
//    private final String username;
//    private final String firstname;
//    private final String lastname;
//    private final String password;
    private final String email;
    private final Collection<? extends GrantedAuthority> authorities;
    private final boolean enabled;
//    private final Date tokenExpirationDate;
    private String userToken;

    public JwtUserDetails(
            Long accountId,
            String email,
            Collection<? extends GrantedAuthority> authorities,
            boolean enabled) {
        this.accountId = accountId;
        this.email = email;
        this.authorities = authorities;
        this.enabled = enabled;
//        this.tokenExpirationDate = tokenExpirationDate;
    }


    //    public JwtUserDetails(
//            Long id,
//            String username,
//            String firstname,
//            String lastname,
//            String email,
//            String password,
//            Collection<? extends GrantedAuthority> authorities,
//            boolean enabled,
//            Date tokenExpirationDate
//    ) {
//        this.id = id;
//        this.username = username;
//        this.firstname = firstname;
//        this.lastname = lastname;
//        this.email = email;
//        this.password = password;
//        this.authorities = authorities;
//        this.enabled = enabled;
//        this.tokenExpirationDate = tokenExpirationDate;
//    }

//    @JsonIgnore
//    public Long getId() {
//        return id;
//    }
//
//    @Override
//    public String getUsername() {
//        return username;
//    }

    @JsonIgnore
    public Long getAccountId() {
        return accountId;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

//    public String getFirstname() {
//        return firstname;
//    }
//
//    public String getLastname() {
//        return lastname;
//    }

    public String getEmail() {
        return email;
    }

//    @JsonIgnore
//    @Override
//    public String getPassword() {
//        return password;
//    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

//    @JsonIgnore
//    public Date getTokenExpirationDate() {
//        return tokenExpirationDate;
//    }


    public String getUserToken() {
        return userToken;
    }

    public void setUserToken(String userToken) {
        this.userToken = userToken;
    }

}

