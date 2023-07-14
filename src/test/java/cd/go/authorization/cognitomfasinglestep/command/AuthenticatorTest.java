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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static java.lang.Boolean.TRUE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticatorTest {
    @Mock
    private Credentials credentials;

    @Mock
    private User user;

    @Mock
    private AuthConfig cognitoAuthConfig;

    @Mock
    private RoleConfig roleConfig;

    @Mock
    private RoleConfiguration roleConfiguration;

    @Mock
    private Configuration configuration;

    private CognitoSingleStepLoginManager loginManager;

    private static final String SECRET = "password123456";
    private static final String BAD_SECRET = "password";
    private static final String USERNAME = "test";
    private static final String PASSWORD = "password";
    private static final String TOTP = "123456";
    private static final String CLIENT_ID = "client-id";
    private static final String REGION = "aws-region";
    private static final String ROLE_NAME = "test-role";
    private static final String MEMBER_OF = "test-group";

    @Test
    public void shouldInitializeTheCognitoPluginWithTheRolesPredicates() {
        when(roleConfig.getName()).thenReturn(ROLE_NAME);
        when(roleConfig.getRoleConfiguration()).thenReturn(roleConfiguration);
        when(roleConfiguration.getMemberOf()).thenReturn(MEMBER_OF);

        try (MockedConstruction<CognitoSingleStepLoginManager> mocked = mockConstruction(CognitoSingleStepLoginManager.class, (mock, context) -> {
            Collection<UserRolePredicate> predicates = (Collection<UserRolePredicate>) context.arguments().get(5);
            assertThat(predicates)
                .hasSize(1)
                .allMatch(predicate -> {
                    assertThat(predicate.getRole())
                        .isEqualTo(ROLE_NAME);
                    assertThat(predicate.test("test-group"))
                        .isTrue();
                    return TRUE;
                });
        })) {
            new Authenticator(cognitoAuthConfig, List.of(roleConfig));
        }
    }

    @Test
    public void shouldAuthenticate() {
        Authenticator authenticator = newAuthenticator();
        when(loginManager.login(USERNAME, PASSWORD, TOTP)).thenReturn(Optional.of(new AuthenticationResponse(user, List.of())));

        Optional<AuthenticationResponse> response = authenticator.authenticate(credentials);

        assertThat(response)
            .isNotEmpty()
            .get()
            .extracting(AuthenticationResponse::getUser)
            .isEqualTo(user);
    }

    @Test
    public void shouldNotAuthenticate() throws Exception {
        Authenticator authenticator = newAuthenticator();
        when(loginManager.login(USERNAME, PASSWORD, TOTP)).thenReturn(Optional.empty());
        assertThat(authenticator.authenticate(credentials))
            .isEmpty();
    }

    @Test
    public void shouldNotAuthenticateIfCredentialsNotContainsTOPT() {
        Authenticator authenticator = newAuthenticator();
        when(credentials.getPassword()).thenReturn(BAD_SECRET);
        assertThat(authenticator.authenticate(credentials))
            .isEmpty();

        try (MockedConstruction<CompoundSecret> mocked = mockConstructionWithAnswer(CompoundSecret.class, invocation -> {
            throw new IllegalArgumentException();
        })) {
            verify(loginManager, never()).login(any(), any(), any());
        }
    }

    @Test
    public void shouldNotAuthenticateIfCognitoConfigNotFound() {
        Authenticator authenticator = newAuthenticator();
        assertThat(authenticator.authenticate(credentials))
            .isEmpty();
    }

    @BeforeEach
    public void setup() {
        when(cognitoAuthConfig.getConfiguration()).thenReturn(configuration);
        when(configuration.getClientId()).thenReturn(CLIENT_ID);
        when(configuration.getRegionName()).thenReturn(REGION);

        lenient().when(credentials.getPassword()).thenReturn(SECRET);
        lenient().when(credentials.getUsername()).thenReturn(USERNAME);
    }

    private Authenticator newAuthenticator() {
        try (MockedConstruction<CognitoSingleStepLoginManager> mocked = mockConstruction(CognitoSingleStepLoginManager.class, (mock, context) -> {
            this.loginManager = mock;
        })) {
            return new Authenticator(cognitoAuthConfig, List.of(roleConfig));
        }
    }
}
