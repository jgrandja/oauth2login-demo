/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Joe Grandja
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class OAuth2LoginApplicationTests {
	static final String CLIENT_REGISTRATION_ID = "client-registration-id";

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void test() throws Exception {
		OAuth2User user = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(user, authorities, CLIENT_REGISTRATION_ID);

		this.mockMvc.perform(get("/resolved")
				.with(authentication(authentication)))
				.andExpect(status().isOk());

		this.mockMvc.perform(get("/not-resolved"))
				.andExpect(status().isUnauthorized());

	}

	private static ClientRegistration createClientRegistration(String registrationId) {
		return ClientRegistration.withRegistrationId(registrationId)
				.redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.scope("openid")
				.authorizationUri("https://example.com/login/oauth/authorize")
				.tokenUri("https://example.com/login/oauth/access_token")
				.jwkSetUri("https://example.com/oauth2/jwk")
				.userInfoUri("https://api.example.com/user")
				.userNameAttributeName("sub")
				.clientName("Client Name")
				.clientId("client-id")
				.clientSecret("client-secret")
				.build();
	}

	@Configuration
	@EnableWebMvc
	static class TestConfig {

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return mockClientRegistrationRepository();
		}

		private ClientRegistrationRepository mockClientRegistrationRepository() {
			ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);
			ClientRegistration clientRegistration = createClientRegistration(CLIENT_REGISTRATION_ID);
			when(clientRegistrationRepository.findByRegistrationId(CLIENT_REGISTRATION_ID)).thenReturn(clientRegistration);
			return clientRegistrationRepository;
		}

		@Bean
		OAuth2AuthorizedClientRepository authorizedClientRepository() {
			return mockAuthorizedClientRepository();
		}

		private OAuth2AuthorizedClientRepository mockAuthorizedClientRepository() {
			OAuth2AuthorizedClientRepository authorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
			OAuth2AuthorizedClient authorizedClient = mock(OAuth2AuthorizedClient.class);
			when(authorizedClientRepository.loadAuthorizedClient(
					eq(CLIENT_REGISTRATION_ID), any(Authentication.class), any(HttpServletRequest.class)))
					.thenReturn(authorizedClient);

			return authorizedClientRepository;
		}

		@RestController
		class TestController {

			@GetMapping("/resolved")
			public String resolved(@RegisteredOAuth2AuthorizedClient(CLIENT_REGISTRATION_ID) OAuth2AuthorizedClient authorizedClient) {
				return "resolved";
			}

			@GetMapping("/not-resolved")
			public String not_resolved(@RegisteredOAuth2AuthorizedClient("invalid-client-registration-id") OAuth2AuthorizedClient authorizedClient) {
				return "not-resolved";
			}
		}
	}
}