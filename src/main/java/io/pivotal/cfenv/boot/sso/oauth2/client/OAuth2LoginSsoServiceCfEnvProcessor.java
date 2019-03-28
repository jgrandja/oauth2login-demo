/*
 * Copyright 2019 the original author or authors.
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
package io.pivotal.cfenv.boot.sso.oauth2.client;

import io.pivotal.cfenv.core.CfCredentials;
import io.pivotal.cfenv.core.CfService;
import io.pivotal.cfenv.spring.boot.CfEnvProcessor;
import io.pivotal.cfenv.spring.boot.CfEnvProcessorProperties;

import java.util.Map;

/**
 * @author Joe Grandja
 */
public class OAuth2LoginSsoServiceCfEnvProcessor implements CfEnvProcessor {
	private static final String OAUTH2_CLIENT_BASE_PROPERTY = "spring.security.oauth2.client";
	private static final String OAUTH2_CLIENT_REGISTRATION_PROPERTY = OAUTH2_CLIENT_BASE_PROPERTY + ".registration";
	private static final String OAUTH2_CLIENT_PROVIDER_PROPERTY = OAUTH2_CLIENT_BASE_PROPERTY + ".provider";
	private static final String PCF_SSO_SERVICE_LABEL = "p-identity";
	private static final String PCF_SSO_SERVICE_BASE_PROPERTY = "pcf.sso.service";
	private static final String PCF_SSO_SERVICE_OAUTH2_LOGIN_REGISTRATION_ID_PROPERTY = PCF_SSO_SERVICE_BASE_PROPERTY + ".oauth2login.registration-id";
	private static final String DEFAULT_CLIENT_REGISTRATION_ID = "pcf-sso";
	private static final String DEFAULT_PROVIDER_ID = "pcf-sso";

	@Override
	public boolean accept(CfService service) {
		return service.existsByLabelStartsWith(PCF_SSO_SERVICE_LABEL);
	}

	@Override
	public void process(CfCredentials cfCredentials, Map<String, Object> properties) {
		String clientId = cfCredentials.getString("client_id");
		String clientSecret = cfCredentials.getString("client_secret");
		String authDomain = cfCredentials.getString("auth_domain");

		// Client properties
		String clientRegistrationIdProperty = OAUTH2_CLIENT_REGISTRATION_PROPERTY + "." + getClientRegistrationId();
		properties.put(clientRegistrationIdProperty + ".provider", DEFAULT_PROVIDER_ID);
		properties.put(clientRegistrationIdProperty + ".client-id", clientId);
		properties.put(clientRegistrationIdProperty + ".client-secret", clientSecret);
		properties.put(clientRegistrationIdProperty + ".client-authentication-method", "basic");
		properties.put(clientRegistrationIdProperty + ".authorization-grant-type", "authorization_code");
		properties.put(clientRegistrationIdProperty + ".redirect-uri", "{baseUrl}/login/oauth2/code/{registrationId}");
		properties.put(clientRegistrationIdProperty + ".scope", "openid, profile, email");

		// Provider properties
		String providerIdProperty = OAUTH2_CLIENT_PROVIDER_PROPERTY + "." + DEFAULT_PROVIDER_ID;
		properties.put(providerIdProperty + ".authorization-uri", authDomain + "/oauth/authorize");
		properties.put(providerIdProperty + ".token-uri", authDomain + "/oauth/token");
		properties.put(providerIdProperty + ".user-info-uri", authDomain + "/userinfo");
		properties.put(providerIdProperty + ".user-name-attribute", "sub");
		properties.put(providerIdProperty + ".jwk-set-uri", authDomain + "/token_keys");
	}

	private String getClientRegistrationId() {
		return DEFAULT_CLIENT_REGISTRATION_ID;
	}

	@Override
	public CfEnvProcessorProperties getProperties() {
		String clientRegistrationIdProperty = OAUTH2_CLIENT_REGISTRATION_PROPERTY + "." + getClientRegistrationId();
		String providerIdProperty = OAUTH2_CLIENT_PROVIDER_PROPERTY + "." + DEFAULT_PROVIDER_ID;
		return CfEnvProcessorProperties.builder()
				.propertyPrefixes(clientRegistrationIdProperty + ", " + providerIdProperty)
				.serviceName("Single Sign On").build();
	}
}