/*
 * Copyright 2019 Banco Bilbao Vizcaya Argentaria, S.A.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cd.go.authorization.cognitomfasinglestep.executor;

import cd.go.authorization.cognitomfasinglestep.command.Authenticator;
import cd.go.authorization.cognitomfasinglestep.model.AuthenticateUserRequest;
import com.google.gson.Gson;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;

import static com.thoughtworks.go.plugin.api.response.DefaultGoApiResponse.SUCCESS_RESPONSE_CODE;

public class UserAuthenticationExecutor implements RequestExecutor {
    private static final Gson GSON = new Gson();
    private final AuthenticateUserRequest request;

    public UserAuthenticationExecutor(GoPluginApiRequest request) {
        this.request = AuthenticateUserRequest.fromJSON(request.requestBody());
    }

    @Override
    public GoPluginApiResponse execute() throws Exception {
        return request.getAuthConfigs().stream()
            .filter(authConfig -> authConfig.getId().equals(COGNITO_AUTH_CONFIG))
            .map(Authenticator::new)
            .flatMap(authenticator -> authenticator.authenticate(request.getCredentials()).stream())
            .map(authenticationResponse -> new DefaultGoPluginApiResponse(SUCCESS_RESPONSE_CODE, authenticationResponse.toJson()))
            .findFirst()
            .orElse(new DefaultGoPluginApiResponse(401));
    }

    private static final String COGNITO_AUTH_CONFIG = "cognito";
}
