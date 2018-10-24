/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestTemplate;
import sample.web.OAuth2AccessTokenResponseConverterWithDefaults;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Joe Grandja
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.oauth2Login()
				.tokenEndpoint()
					.accessTokenResponseClient(authorizationCodeTokenResponseClient())
					.and()
				.userInfoEndpoint()
					.userService(oauth2UserService());
	}
	// @formatter:on

	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient() {
		OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter =
				new OAuth2AccessTokenResponseHttpMessageConverter();
		tokenResponseHttpMessageConverter.setTokenResponseConverter(new OAuth2AccessTokenResponseConverterWithDefaults());

		RestTemplate restTemplate = new RestTemplate(Arrays.asList(
				new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

		DefaultAuthorizationCodeTokenResponseClient tokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		tokenResponseClient.setRestOperations(restTemplate);

		return tokenResponseClient;
	}

	private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		enhanceJsonMessageConverter(restTemplate);

		DefaultOAuth2UserService oauth2UserService = new DefaultOAuth2UserService();
		oauth2UserService.setRestOperations(restTemplate);

		return oauth2UserService;
	}

	private void enhanceJsonMessageConverter(RestTemplate restTemplate) {
		// NOTE:
		// Facebook's UserInfo API -> https://graph.facebook.com/me
		// returns "text/javascript; charset=UTF-8" for the "content-type" response header
		// even though the content is JSON. This is not correct and should be reported to Facebook to fix.
		//
		// This is a temporary workaround that adds "text/javascript; charset=UTF-8"
		// as a supported MediaType in MappingJackson2HttpMessageConverter,
		// which is used to convert the UserInfo response to a Map.

		HttpMessageConverter<?> jsonMessageConverter = restTemplate.getMessageConverters().stream()
				.filter(c -> c instanceof  MappingJackson2HttpMessageConverter)
				.findFirst()
				.orElse(null);

		if (jsonMessageConverter == null) {
			return;
		}

		List<MediaType> supportedMediaTypes = new ArrayList<>(jsonMessageConverter.getSupportedMediaTypes());
		supportedMediaTypes.add(MediaType.valueOf("text/javascript;charset=UTF-8"));
		((AbstractHttpMessageConverter) jsonMessageConverter).setSupportedMediaTypes(supportedMediaTypes);
	}
}