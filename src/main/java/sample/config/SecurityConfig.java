/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import org.apache.http.client.HttpClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.web.client.RestOperations;

import java.util.Arrays;

/**
 * @author Joe Grandja
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient;

	@Autowired
	private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;

	@Autowired
	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests(authorizeRequests ->
				authorizeRequests
					.anyRequest().authenticated())
			.oauth2Login(oauth2Login ->
				oauth2Login
					.tokenEndpoint(tokenEndpoint ->
						tokenEndpoint
							.accessTokenResponseClient(this.authorizationCodeTokenResponseClient))
					.userInfoEndpoint(userInfoEndpoint ->
						userInfoEndpoint
							.userService(this.oauth2UserService)
							.oidcUserService(this.oidcUserService)));
	}
	// @formatter:on

	@Bean
	public RestOperations tokenEndpointRestOperations(RestTemplateBuilder builder, HttpClient mtlsHttpClient) {
		return builder
				.requestFactory(() -> new HttpComponentsClientHttpRequestFactory(mtlsHttpClient))
				.messageConverters(Arrays.asList(
						new FormHttpMessageConverter(),
						new OAuth2AccessTokenResponseHttpMessageConverter(),
						new MappingJackson2HttpMessageConverter()))
				.errorHandler(new OAuth2ErrorResponseErrorHandler())
				.build();
	}

	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient(
			RestOperations tokenEndpointRestOperations) {
		DefaultAuthorizationCodeTokenResponseClient tokenResponseClient =
				new DefaultAuthorizationCodeTokenResponseClient();
		tokenResponseClient.setRestOperations(tokenEndpointRestOperations);
		return tokenResponseClient;
	}

	@Bean
	public RestOperations userInfoEndpointRestOperations(RestTemplateBuilder builder, HttpClient mtlsHttpClient) {
		return builder
				.requestFactory(() -> new HttpComponentsClientHttpRequestFactory(mtlsHttpClient))
				.errorHandler(new OAuth2ErrorResponseErrorHandler())
				.build();
	}

	@Bean
	public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(
			RestOperations userInfoEndpointRestOperations) {
		DefaultOAuth2UserService userService = new DefaultOAuth2UserService();
		userService.setRestOperations(userInfoEndpointRestOperations);
		return userService;
	}

	@Bean
	public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(
			OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
		OidcUserService userService = new OidcUserService();
		userService.setOauth2UserService(oauth2UserService);
		return userService;
	}

	@Bean
	public RestOperations jwksEndpointRestOperations(RestTemplateBuilder builder, HttpClient tlsHttpClient) {
		return builder
				.requestFactory(() -> new HttpComponentsClientHttpRequestFactory(tlsHttpClient))
				.build();
	}

	@Bean
	public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory(RestOperations jwksEndpointRestOperations) {
		return new IdTokenDecoderFactory(jwksEndpointRestOperations);
	}
}