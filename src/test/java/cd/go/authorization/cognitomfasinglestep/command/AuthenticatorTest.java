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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.powermock.api.mockito.PowerMockito.whenNew;

@PrepareForTest(Authenticator.class)
@RunWith(PowerMockRunner.class)
public class AuthenticatorTest {

    @Test
    public void shouldAuthenticate() {
        when(loginManager.login(USERNAME, PASSWORD, TOTP)).thenReturn(user);

        AuthenticationResponse response = authenticator.authenticate(credentials, Arrays.asList(cognitoAuthConfig));

        assertThat(response)
            .isNotNull();
        assertThat(response.getUser())
            .isEqualTo(user);
        assertThat(response.getConfigUsedForAuthentication())
            .isEqualTo(cognitoAuthConfig);
    }

    @Test
    public void shouldNotAuthenticate() throws Exception {
        when(loginManager.login(USERNAME, PASSWORD, TOTP)).thenReturn(null);
        assertThat(authenticator.authenticate(credentials, Arrays.asList(cognitoAuthConfig)))
            .isNull();
    }

    @Test
    public void shouldNotAuthenticateIfCredentialsNotContainsTOPT() {
        when(credentials.getPassword()).thenReturn(BAD_SECRET);
        assertThat(authenticator.authenticate(credentials, Arrays.asList(cognitoAuthConfig)))
            .isNull();
        verify(loginManager, never()).login(any(), any(), any());
    }

    @Test
    public void shouldNotAuthenticateIfCognitoConfigNotFound() {
        assertThat(authenticator.authenticate(credentials, Arrays.asList(otherAuthConfig)))
            .isNull();
    }

    @Before
    public void setup() throws Exception {
        when(otherAuthConfig.getId()).thenReturn("other");

        when(cognitoAuthConfig.getId()).thenReturn("cognito");
        when(cognitoAuthConfig.getConfiguration()).thenReturn(configuration);
        when(configuration.getClientId()).thenReturn(CLIENT_ID);
        when(configuration.getRegionName()).thenReturn(REGION);

        when(credentials.getPassword()).thenReturn(SECRET);
        when(credentials.getUsername()).thenReturn(USERNAME);

        whenNew(CognitoSingleStepLoginManager.class).withAnyArguments().thenReturn(loginManager);

        this.authenticator = new Authenticator();
    }

    @Mock
    private Credentials credentials;

    @Mock
    private User user;

    @Mock
    private AuthConfig cognitoAuthConfig, otherAuthConfig;

    @Mock
    private Configuration configuration;

    @Mock
    private CognitoSingleStepLoginManager loginManager;

    @Mock
    private List<AuthConfig> authConfigs;

    @Mock
    private CompoundSecret compoundSecret;

    private Authenticator authenticator;

    private static final String SECRET = "password123456";
    private static final String BAD_SECRET = "password";
    private static final String USERNAME = "test";
    private static final String PASSWORD = "password";
    private static final String TOTP = "123456";
    private static final String CLIENT_ID = "client-id";
    private static final String REGION = "aws-region";
}
