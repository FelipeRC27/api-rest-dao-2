package com.idat.idatapirest.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

@EnableAuthorizationServer
@Configuration
public class Auth2Config extends AuthorizationServerConfigurerAdapter{

	@Autowired
	private TokenStore store;
	
	@Autowired
	private AuthenticationManager authentication;
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		// TODO Auto-generated method stub
		super.configure(security);
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		//Creamos usuario en memoria
		clients.inMemory()
		.withClient("felipe")
		.secret(new BCryptPasswordEncoder().encode("felipe"))
		.authorizedGrantTypes("password","authorization_code", "refreh_token", "implicit")
		.scopes("read","whrite","trust")
		.accessTokenValiditySeconds(60*60*2);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		
		endpoints.tokenStore(store).authenticationManager(authentication);	
	}
	
}
