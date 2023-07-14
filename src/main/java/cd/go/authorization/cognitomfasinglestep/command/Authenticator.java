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
import cd.go.authorization.cognitomfasinglestep.cognito.UserRolePredicate;
import cd.go.authorization.cognitomfasinglestep.model.*;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class Authenticator {
    private final CognitoSingleStepLoginManager loginManager;

    public Authenticator(AuthConfig authConfig) {
        this(authConfig, List.of());
    }

    public Authenticator(AuthConfig authConfig, Collection<RoleConfig> roleConfigs) {
        Configuration config = authConfig.getConfiguration();
        loginManager = new CognitoSingleStepLoginManager(config.getUserPoolId(), config.getClientId(), config.getAppSecret(), config.getRegionName(), config.getExecutionRoleARN(), buildRolePredicates(roleConfigs));
    }

    public Optional<AuthenticationResponse> authenticate(Credentials credentials) {
        try {
            CompoundSecret secret = new CompoundSecret(credentials.getPassword());
            return loginManager.login(credentials.getUsername(), secret.getPassword(), secret.getTOTP());
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private Collection<UserRolePredicate> buildRolePredicates(Collection<RoleConfig> roleConfigs) {
        return roleConfigs.stream()
            .map(roleConfig -> new UserRolePredicate(roleConfig.getName()) {
                @Override
                public boolean test(String userGroup) {
                    return userGroup.equals(roleConfig.getRoleConfiguration().getMemberOf());
                }
            })
            .collect(Collectors.toList());
    }

    public boolean existUser(String username) {
        return loginManager.isValidUser(username);
    }

}
