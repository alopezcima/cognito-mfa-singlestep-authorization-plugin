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

package cd.go.authorization.cognitomfasinglestep.command;

import cd.go.authorization.cognitomfasinglestep.cognito.CognitoSingleStepLoginManager;
import cd.go.authorization.cognitomfasinglestep.model.*;

import java.util.List;

public class Authenticator {
    public AuthenticationResponse authenticate(Credentials credentials, List<AuthConfig> authConfigs) {
        try {
            CompoundSecret secret = new CompoundSecret(credentials.getPassword());
            for (AuthConfig authConfig : authConfigs) {
                if (authConfig.getId().equals(COGNITO_AUTH_CONFIG)) {
                    Configuration config = authConfig.getConfiguration();
                    CognitoSingleStepLoginManager loginManager = new CognitoSingleStepLoginManager(config);
                    User user = loginManager.login(credentials.getUsername(), secret.getPassword(), secret.getTOTP());
                    if (user == null) {
                        return null;
                    }
                    return new AuthenticationResponse(user, authConfig);
                }
            }
            return null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static final String COGNITO_AUTH_CONFIG = "cognito";
}
