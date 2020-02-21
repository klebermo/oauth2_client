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
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.endpoint.NimbusAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import java.util.List;
import java.util.ArrayList;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;

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
          .oauth2Client(c -> c
              .authorizationCodeGrant()
                  .authorizationRequestRepository(new HttpSessionOAuth2AuthorizationRequestRepository())
                  .authorizationRequestResolver(new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository(), "http://localhost:8080/oauth/authorize"))
          )
					.oauth2Login(l -> l
              .clientRegistrationRepository(clientRegistrationRepository())
          );
	}

  @Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
  		List<ClientRegistration> registrations = new ArrayList<>();
  		registrations.add(clientRegistration());
  		return new InMemoryClientRegistrationRepository(registrations);
	}

  private ClientRegistration clientRegistration() {
    return ClientRegistration.withRegistrationId("server")
        .clientId("first-client")
        .clientSecret("noonewilleverguess")
        .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .scope("read")
        .redirectUriTemplate("{baseUrl}/")
        .authorizationUri("http://localhost:8080/oauth/authorize")
        .tokenUri("http://localhost:8080/oauth2/check_token")
        .userInfoUri("http://localhost:8080/oauth2/userinfo")
        .jwkSetUri("http://localhost:8080/.well-known/jwks.json")
        .userInfoAuthenticationMethod(AuthenticationMethod.FORM)
        .clientName("server").build();
  }
}
