package bg.softuni.mobilelele.config;

import bg.softuni.mobilelele.user.MobileleleUserDetailsService;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final MobileleleUserDetailsService mobileleleUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(MobileleleUserDetailsService mobileleleUserDetailsService, PasswordEncoder passwordEncoder) {
        this.mobileleleUserDetailsService = mobileleleUserDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override // Authentication - Done here!
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(mobileleleUserDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    @Override // Authorisation - set permissions and endpoints here
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/js/**", "/css/**", "/img/**").permitAll()
                .antMatchers("/", "/home", "/users/login", "/users/register",
                        "/offers/all", "/brands/all").permitAll()
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/users/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .defaultSuccessUrl("/")
                .failureForwardUrl("/users/login")
                .and()
                .logout().logoutUrl("/users/logout")
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID");
    }
}
