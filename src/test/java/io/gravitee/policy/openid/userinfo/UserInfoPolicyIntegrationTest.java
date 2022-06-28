/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.openid.userinfo;

import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.policy.PolicyBuilder;
import io.gravitee.apim.gateway.tests.sdk.resource.ResourceBuilder;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.plugin.policy.PolicyPlugin;
import io.gravitee.plugin.resource.ResourcePlugin;
import io.gravitee.policy.openid.userinfo.configuration.UserInfoPolicyConfiguration;
import io.reactivex.observers.TestObserver;
import io.vertx.reactivex.core.buffer.Buffer;
import io.vertx.reactivex.ext.web.client.HttpRequest;
import io.vertx.reactivex.ext.web.client.HttpResponse;
import io.vertx.reactivex.ext.web.client.WebClient;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
@GatewayTest
@DeployApi("/apis/user-info.json")
class UserInfoPolicyIntegrationTest extends AbstractPolicyTest<UserInfoPolicy, UserInfoPolicyConfiguration> {

    public static final String PAYLOAD_EXTRACTION_PATH = "/payload-extraction";
    public static final String NO_PAYLOAD_EXTRACTION_PATH = "/no-payload-extraction";

    public static final String CAUSING_ERROR_TOKEN = "causing_error_token";

    @Override
    public void configureResources(Map<String, ResourcePlugin> resources) {
        resources.put("dummy-oauth", ResourceBuilder.build("dummy-oauth", DummyOauth2Resource.class));
    }

    @Override
    public void configurePolicies(Map<String, PolicyPlugin> policies) {
        policies.put(
            "copy-attribute-to-response",
            PolicyBuilder.build("copy-attribute-to-response", CopyAttributeToResponsePayloadPolicy.class)
        );
    }

    @ParameterizedTest
    @DeployApi("/apis/user-info-without-resource.json")
    @ValueSource(strings = { PAYLOAD_EXTRACTION_PATH, NO_PAYLOAD_EXTRACTION_PATH })
    @DisplayName("Should not be authorized because of no auth server found for configuration")
    void shouldNotBeAuthorizedWithoutResource(String flowPath, WebClient webClient) {
        wiremock.stubFor(get("/endpoint").willReturn(ok("I'm the backend")));

        final TestObserver<HttpResponse<Buffer>> obs = webClient.get("/test-no-resource" + flowPath).rxSend().test();
        awaitTerminalEvent(obs)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.bodyAsString()).isEqualTo("No OpenID Connect authorization server has been configured");

                return true;
            });

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @ParameterizedTest(name = "Header: ''{1}''")
    @MethodSource("provideEmptyOrNotBearerAuthorizationHeaders")
    @DisplayName("Should not be authorized because of bad Authorization header")
    void shouldNotBeAuthorizedWithWrongHeader(HttpHeaders headers, String testName, WebClient webClient) {
        wiremock.stubFor(get("/endpoint").willReturn(ok("I'm the backend")));

        final HttpRequest<Buffer> request = webClient.get("/test" + PAYLOAD_EXTRACTION_PATH);

        headers.forEach(h -> request.putHeader(h.getKey(), h.getValue()));

        final TestObserver<HttpResponse<Buffer>> obs = request.rxSend().test();
        awaitTerminalEvent(obs)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.bodyAsString()).isEqualTo("No OAuth authorization header was supplied");
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Bearer realm=gravitee.io - No OAuth authorization header was supplied");
                return true;
            });

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should not be authorized because of bad empty Bearer access token")
    void shouldNotBeAuthorizedWithEmptyBearerToken(WebClient webClient) {
        wiremock.stubFor(get("/endpoint").willReturn(ok("I'm the backend")));

        final TestObserver<HttpResponse<Buffer>> obs = webClient
            .get("/test" + PAYLOAD_EXTRACTION_PATH)
            .putHeader(HttpHeaderNames.AUTHORIZATION, "Bearer")
            .rxSend()
            .test();
        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.bodyAsString()).isEqualTo("No OAuth access token was supplied");
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Bearer realm=gravitee.io - No OAuth access token was supplied");
                return true;
            });

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should not be authorized when token is invalid in the resource")
    void shouldBeAuthorized(WebClient webClient) {
        wiremock.stubFor(get("/endpoint").willReturn(ok("I'm the backend")));

        final TestObserver<HttpResponse<Buffer>> obs = webClient
            .get("/test" + NO_PAYLOAD_EXTRACTION_PATH)
            .putHeader(HttpHeaderNames.AUTHORIZATION, "Bearer invalid_token")
            .rxSend()
            .test();
        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Bearer realm=gravitee.io - Invalid OAuth access token was supplied");
                assertThat(response.bodyAsString()).contains(DummyOauth2Resource.EXTRACTED_FAIL_PAYLOAD);
                return true;
            });

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @Test
    @DisplayName("Should receive 503 - Service Unavailable when resource throws")
    void shouldReturn503(WebClient webClient) {
        wiremock.stubFor(get("/endpoint").willReturn(ok("I'm the backend")));

        final TestObserver<HttpResponse<Buffer>> obs = webClient
            .get("/test" + NO_PAYLOAD_EXTRACTION_PATH)
            .putHeader(HttpHeaderNames.AUTHORIZATION, "Bearer " + CAUSING_ERROR_TOKEN)
            .rxSend()
            .test();
        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(503);
                assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo(
                        "Bearer realm=gravitee.io - Error occurs during OAuth access token validation: " +
                        DummyOauth2Resource.THROWABLE_MESSAGE
                    );
                assertThat(response.bodyAsString()).contains("Service Unavailable");
                return true;
            });

        wiremock.verify(exactly(0), getRequestedFor(urlPathEqualTo("/endpoint")));
    }

    @ParameterizedTest
    @ValueSource(strings = { PAYLOAD_EXTRACTION_PATH, NO_PAYLOAD_EXTRACTION_PATH })
    @DisplayName("Should be authorized and get user info if configured")
    void shouldBeAuthorized(String flowPath, WebClient webClient) {
        wiremock.stubFor(get("/endpoint" + flowPath).willReturn(ok("I'm the backend")));

        final TestObserver<HttpResponse<Buffer>> obs = webClient
            .get("/test" + flowPath)
            .putHeader(HttpHeaderNames.AUTHORIZATION, "Bearer " + flowPath)
            .rxSend()
            .test();
        awaitTerminalEvent(obs);
        obs
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                if (PAYLOAD_EXTRACTION_PATH.equals(flowPath)) {
                    assertThat(response.bodyAsString()).contains(DummyOauth2Resource.EXTRACTED_PAYLOAD);
                } else if (NO_PAYLOAD_EXTRACTION_PATH.equals(flowPath)) {
                    assertThat(response.bodyAsString()).contains(CopyAttributeToResponsePayloadPolicy.NO_CONTENT);
                }
                return true;
            });

        wiremock.verify(exactly(1), getRequestedFor(urlPathEqualTo("/endpoint" + flowPath)));
    }

    private static Stream<Arguments> provideEmptyOrNotBearerAuthorizationHeaders() {
        return Stream.of(
            Arguments.of(HttpHeaders.create(), "No Authorization header"),
            Arguments.of(HttpHeaders.create().add(HttpHeaderNames.AUTHORIZATION, (CharSequence) null), "null"),
            Arguments.of(HttpHeaders.create().add(HttpHeaderNames.AUTHORIZATION, ""), ""),
            Arguments.of(HttpHeaders.create().add(HttpHeaderNames.AUTHORIZATION, "Basic"), "Basic")
        );
    }
}
