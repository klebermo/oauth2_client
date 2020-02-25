package oauth.client;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.config.Customizer;

@Configuration
@EnableWebSecurity
@EnableOAuth2Sso
@Order(1)
public class Security extends WebSecurityConfigurerAdapter {
  @Override
	public void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
							.antMatchers("/**", "/login**" ,"/css/**", "/js/**", "/img/**").permitAll()
							.anyRequest().authenticated()
          .and()
					.exceptionHandling()
							.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
          .and()
					.csrf()
	            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
          .and()
					.logout()
							.logoutUrl("/logout")
					    .logoutSuccessUrl("/").permitAll()
          .and()
					.oauth2Login(Customizer.withDefaults());
	}
}
