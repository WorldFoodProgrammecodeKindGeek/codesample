package care.fullcircle.security;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import javax.servlet.Filter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public interface ISecuredApplication {

    @Bean
    public FilterRegistrationBean authorizationFilterRegistration();

    @Bean(name = "jwtFilter")
    public Filter jwtAuthenticationFilter();

}
