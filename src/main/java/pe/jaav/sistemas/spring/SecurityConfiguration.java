package pe.jaav.sistemas.spring;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import pe.jaav.sistemas.spring.security.AwsCognitoJwtAuthenticationFilter;
import pe.jaav.sistemas.spring.security.AwsCognitoRSAKeyProvider;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Value("${awsregion}")
	private String awsCognitoRegion;
	
	@Value("${userPoolId}")
	private String awsUserPoolsId;

	@Value("${enableSecurity}")
	private String enableSecurity;
	
	@Bean
	public JWTVerifier beanJWTVerifier() throws IOException {
		RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(awsCognitoRegion, awsUserPoolsId);
		Algorithm algorithm = Algorithm.RSA256(keyProvider);
    	JWTVerifier jwtVerifier = JWT.require(algorithm).build();
		return jwtVerifier;
	}
	
	@Autowired
	private AwsCognitoJwtAuthenticationFilter awsCognitoJwtAuthenticationFilter;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
    	boolean filtrarPorSeguridad = false;
    	if("S".equals(enableSecurity)){
    		filtrarPorSeguridad = true;
    	}
    	
    	/**Verificamos si esta ACTIVA el filtrado de seguridad*/
    	if(filtrarPorSeguridad){
    		http.headers().cacheControl();
    		http
    			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
    			.csrf().disable()
    				.authorizeRequests()
    					.antMatchers(HttpMethod.OPTIONS,"/api/**").permitAll()
    					.antMatchers(HttpMethod.GET,"/v2/api-docs").permitAll()
    					.antMatchers(HttpMethod.POST,"/api/security/login").permitAll()
    					.antMatchers(HttpMethod.POST,"/api/security/first-reset-password").permitAll()
    					.antMatchers(HttpMethod.POST,"/api/security/change-password").permitAll()
    					.antMatchers(HttpMethod.POST,"/api/security/refresh-token").permitAll()
    					.antMatchers(HttpMethod.POST,"/api/security/signout*").permitAll()
    					.antMatchers("/api/**").authenticated()
    					.antMatchers("/**").permitAll()
    					.anyRequest().authenticated()
    				.and()
    				.addFilterBefore(awsCognitoJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);		
    	}else{
    		http.csrf().disable().authorizeRequests()
            .antMatchers("/").permitAll()
			.antMatchers("/**").permitAll()
			.anyRequest().authenticated()
            ;            
    	}
    	

	}

}
