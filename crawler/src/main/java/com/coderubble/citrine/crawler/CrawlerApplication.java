package com.coderubble.citrine.crawler;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.*;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;

import java.lang.annotation.*;

@SpringBootApplication
public class CrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrawlerApplication.class, args);
    }
}

@RestController
class Endpoint {
    @RequestMapping("/hi")
    @SecuredResource
    public String sayhi() {
        return "{name:'citrine',says,'hi-2'}";
    }
}

@Documented
@Target(ElementType.METHOD)
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@interface SecuredResource {
    boolean exclude() default false;
}

class SecuredResourceConditional implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        boolean secured = context.getEnvironment().getProperty("secure.resource.enabled", Boolean.class);
        if (secured) {
            System.setProperty("keycloak.auth-server-url", "http://localhost:8080/auth");
            System.setProperty("keycloak.realm", "master");
            System.setProperty("keycloak.resource", "citrine");
            System.setProperty("keycloak.public-client", "true");
        }
        return secured;
    }
}

@Configuration
@ComponentScan(
        basePackageClasses = KeycloakSecurityComponents.class,
        excludeFilters = @ComponentScan.Filter(type = FilterType.REGEX, pattern = "org.keycloak.adapters.springsecurity.management.HttpSessionManager"))
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Conditional(SecuredResourceConditional.class)
class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http.authorizeRequests()
                .antMatchers("/hi")
                .hasRole("citrine_role")
                .anyRequest()
                .permitAll();
    }
}