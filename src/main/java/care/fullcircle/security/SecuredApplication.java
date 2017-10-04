package care.fullcircle.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import javax.servlet.Filter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public abstract class SecuredApplication implements ISecuredApplication {

    @Value("#{'${secured.url.pattern:/*}'}")
    private String securedUrlPattern;


    @Bean
    public FilterRegistrationBean authorizationFilterRegistration() {

        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter((Filter) jwtAuthenticationFilter());

        // set path to be secured with the filter
        registration.addUrlPatterns(securedUrlPattern);
        registration.addInitParameter("paramName", "paramValue");
        registration.setName("jwtFilter");
        registration.setOrder(1);
        return registration;
    }


    @Bean(name = "jwtFilter")
    public Filter jwtAuthenticationFilter() {
        return (new JwtAuthenticationTokenFilter());
    }

}
