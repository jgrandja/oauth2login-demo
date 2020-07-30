/*
 * Copyright 2002-2020 the original author or authors.
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
package sample.config;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;

import javax.net.ssl.SSLContext;

/**
 * @author Joe Grandja
 */
@Configuration
public class HttpClientConfig {
    private static final String KEYSTORE_TYPE = "pkcs12";
    private static final String KEYSTORE_PATH = "classpath:curity-oauth2-client.p12";
    private static final String KEYSTORE_PASSWORD = "secret";

    @Bean
    public HttpClient mtlsHttpClient() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .setKeyStoreType(KEYSTORE_TYPE)
                .loadKeyMaterial(
                        ResourceUtils.getFile(KEYSTORE_PATH),
                        KEYSTORE_PASSWORD.toCharArray(),
                        KEYSTORE_PASSWORD.toCharArray())
                .loadTrustMaterial(
                        ResourceUtils.getFile(KEYSTORE_PATH),
                        KEYSTORE_PASSWORD.toCharArray())
                .build();

        return HttpClients.custom()
                .setSSLContext(sslContext)
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();
    }

    @Bean
    public HttpClient tlsHttpClient() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .loadTrustMaterial(
                        ResourceUtils.getFile(KEYSTORE_PATH),
                        KEYSTORE_PASSWORD.toCharArray())
                .build();

        return HttpClients.custom()
                .setSSLContext(sslContext)
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();
    }
}