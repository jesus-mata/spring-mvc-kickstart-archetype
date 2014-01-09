package ${package}.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;

import ${package}.account.UserService;

@Configuration
@EnableWebSecurity
// @ImportResource(value = "classpath:spring-security-context.xml") //Uncomment this line if you want to use spring XML configuration instead of Java based config
class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final String REMEBER_ME_KEY = "remember-me-key";

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/resources/**","/favicon.ico");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.headers().disable().
			authorizeRequests()
				.antMatchers("/signup", "/signin", "/").permitAll()
				.anyRequest().authenticated()
				.and().formLogin().loginPage("/signin").loginProcessingUrl("/login").failureUrl("/signin?error=1").defaultSuccessUrl("/").permitAll()
				.and().logout().logoutUrl("/logout")
			.and().rememberMe().rememberMeServices(rememberMeServices()).key(REMEBER_ME_KEY);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.eraseCredentials(true).userDetailsService(userService()).passwordEncoder(passwordEncoder());
	}

	@Bean
	public UserService userService() {
		return new UserService();
	}

	@Bean
	public TokenBasedRememberMeServices rememberMeServices() {
		return new TokenBasedRememberMeServices(REMEBER_ME_KEY, userService());
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new StandardPasswordEncoder(); // For Simple apps

		// 175 of strength a.k.a. the log rounds to use
		// return new BCryptPasswordEncoder(175);
	}
}