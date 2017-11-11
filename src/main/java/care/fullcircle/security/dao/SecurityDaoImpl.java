package care.fullcircle.security.dao;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.rowset.SqlRowSet;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import javax.annotation.Resource;

/**
 * Created by oleh kuprovskyi on 11.11.17.
 */

//access_tokens

@Repository
public class SecurityDaoImpl {

    private final static String GET_TOKEN_ROLES = "SELECT u.id, u.username, u.email, o.expires_at, u.roles, u.enabled FROM oauth2_access_tokens o join fos_user u on o.user_id = u.id where enabled=1 and token = ?";
    private final Logger LOG = LoggerFactory.getLogger(this.getClass());
    @Resource
    protected JdbcTemplate jdbc;

    public UserDetails getTokenRoles(String token) {
        UserDetails userDetails = null;
        Object[] parameters = new Object[] { token };
        SqlRowSet set = jdbc.queryForRowSet(GET_TOKEN_ROLES, parameters);
        LOG.debug("set " + set);
//        if (set.next()) {
//            LOG.debug("getTokenRoles returned result from DB");
//            long id = set.getLong(1);
//            String userName = set.getString(2);
//            String email = set.getString(3);
//            Date date = new Date(set.getLong(4)*1000);
//            String roles = set.getString(5);
//            boolean enabled = set.getBoolean(6);
//
//            // parse and add the user role
//            LOG.debug("*** roles: " + roles);
//            String roleName = roles.substring(roles.indexOf("\"") + 1, roles.lastIndexOf("\""));
//            LOG.debug("*** roleName: " + roleName);
//            GrantedAuthority auth = new SimpleGrantedAuthority(roleName);
//            ArrayList<GrantedAuthority> rolesList = new ArrayList<>();
//            rolesList.add(auth);
//
//            // create the userDetails object
////            userDetails = new JwtUserDetails(accountId, email, roles, true, ip, fingerprint);
//            userDetails = new JwtUserDetails(id, userName, userName, userName, email, "password", rolesList, enabled, date);
//        }

        LOG.debug("getTokenRoles returns " + userDetails);
        return (userDetails);
    }

}
