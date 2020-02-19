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

@Configuration
@EnableWebSecurity
@EnableOAuth2Sso
@Order(1)
public class Security extends WebSecurityConfigurerAdapter {
  @Override
	public void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests(a -> a
							.antMatchers("/", "/error", "/css/**", "/js/**", "/img/**").permitAll()
							.anyRequest().authenticated()
					)
					.exceptionHandling(e -> e
							.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
					)
					.csrf(c -> c
	            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
	        )
					.logout(l -> l
							.logoutUrl("/logout")
					    .logoutSuccessUrl("/").permitAll()
					)
					.oauth2Login();
	}
}
