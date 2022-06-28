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

import static io.gravitee.policy.openid.userinfo.UserInfoPolicyIntegrationTest.CAUSING_ERROR_TOKEN;
import static io.gravitee.policy.openid.userinfo.UserInfoPolicyIntegrationTest.NO_PAYLOAD_EXTRACTION_PATH;
import static io.gravitee.policy.openid.userinfo.UserInfoPolicyIntegrationTest.PAYLOAD_EXTRACTION_PATH;

import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.resource.api.ResourceConfiguration;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
public class DummyOauth2Resource extends OAuth2Resource<DummyOauth2Resource.DummyOauth2ResourceConfiguration> {

    public static final String EXTRACTED_PAYLOAD = "Extracted payload!";
    public static final String EXTRACTED_FAIL_PAYLOAD = "Extracted fail payload!";
    public static final String THROWABLE_MESSAGE = "Throwable message";

    @Override
    public void introspect(String token, Handler handler) {}

    @Override
    public void userInfo(String token, Handler<UserInfoResponse> handler) {
        UserInfoResponse response = new UserInfoResponse(false, EXTRACTED_FAIL_PAYLOAD);
        if (PAYLOAD_EXTRACTION_PATH.equals(token) || NO_PAYLOAD_EXTRACTION_PATH.equals(token)) {
            response = new UserInfoResponse(true, EXTRACTED_PAYLOAD);
        } else if (CAUSING_ERROR_TOKEN.equals(token)) {
            response = new UserInfoResponse(new RuntimeException(THROWABLE_MESSAGE));
        }

        handler.handle(response);
    }

    public static class DummyOauth2ResourceConfiguration implements ResourceConfiguration {}
}
