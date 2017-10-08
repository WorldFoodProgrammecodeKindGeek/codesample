package care.fullcircle.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.filter.GenericFilterBean;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtAuthenticationTokenFilter  extends GenericFilterBean {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Value("${jwt.header}")
    private String tokenHeader;

    @Value("${external.url.pattern:#{null}}")
    private String externalUrlPattern;

    @Value("${access.control.allow.origin:#{'http://admin.telemed.com'}}")
    private String allowOrigin;

    @Resource
    private SecurityService security;


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        log.debug("Security filter request - " + httpRequest.getRequestURI());

        // quick route - if external
        if (externalUrlPattern != null && !externalUrlPattern.isEmpty()) {
//            log.info("looking for pattern " + externalUrlPattern + " in URI " + ((HttpServletRequest)servletRequest).getRequestURI());
            Pattern p = Pattern.compile(externalUrlPattern);
            Matcher m = p.matcher(((HttpServletRequest)servletRequest).getRequestURI());
            if(m.find()){
                log.info("security check - external URI " + ((HttpServletRequest)servletRequest).getRequestURI() + " is verified for pattern " + externalUrlPattern);
                filterChain.doFilter(servletRequest, servletResponse);
                return;
            }
        }


        // exclude OPTIONS tests for Aharon
        if ( httpRequest.getMethod().equals(RequestMethod.OPTIONS.name()) ) {
            log.debug("security check - passing method " + RequestMethod.OPTIONS.name());
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }


        // check token
        String fullToken = httpRequest.getHeader(this.tokenHeader);
        if (StringUtils.isEmpty(fullToken)) {
            setErrorResponse(servletResponse, "No bearer token available");
            return;
        } else {
            String authToken = fullToken.substring("Bearer".length() + 1, fullToken.length());
            log.debug("Security filter activated for " + httpRequest.getRequestURI() + " with token " + authToken);

            // verify token validity
            boolean valid = security.isTokenValid(authToken);
            if (!valid) {
                setErrorResponse(servletResponse, "Not a valid token");
                return;
            }

            // check expiration
            boolean expired = security.isTokenExpired(authToken);
            if(expired) {
                setErrorResponse(servletResponse, "Token expired");
                return;
            }

            // get user credentials
            UserDetails userDetails = security.getUserByToken(authToken);

            // set user credentials to context
            UsernamePasswordAuthenticationToken userPassToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            userPassToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
            SecurityContextHolder.getContext().setAuthentication(userPassToken);

            log.debug("continue with the chain...");
            if (log.isTraceEnabled()){
                traceSession(servletRequest);
            }

            HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
            httpResponse.addHeader("Access-Control-Allow-Origin",allowOrigin);
            filterChain.doFilter(servletRequest, servletResponse);
        }

    }


    //=======================
    private void setErrorResponse(ServletResponse response, String msg) throws IOException {
        log.warn("Token error - " + msg);
        ((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        ((HttpServletResponse) response).setHeader("WWW-Authenticate","Bearer realm=\"Service\", error=\"invalid_grant\", error_description=\"" + msg + ".\"");
    }


    //=======================
    private void traceSession(ServletRequest request) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        Enumeration<String> headerNames = httpRequest.getHeaderNames();
        log.trace(((HttpServletRequest) request).getRequestURL().toString());
        log.trace(((HttpServletRequest) request).getQueryString());
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                log.trace("Header: " + httpRequest.getHeader(headerNames.nextElement()));
            }
        }
    }

}