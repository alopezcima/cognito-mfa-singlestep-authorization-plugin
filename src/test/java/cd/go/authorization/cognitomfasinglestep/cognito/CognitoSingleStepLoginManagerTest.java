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

package cd.go.authorization.cognitomfasinglestep.cognito;

import cd.go.authorization.cognitomfasinglestep.exception.InvalidCognitoUserStateException;
import cd.go.authorization.cognitomfasinglestep.model.Configuration;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CognitoSingleStepLoginManagerTest {
    private static final String COGNITO_POOL_ID = "poolId";
    private static final String COGNITO_CLIENT_ID = "clientid";
    private static final String USERNAME = "USER";
    private static final String PASSWORD = "PASS";
    private static final String APP_SECRET = "SECRET";
    private static final String SECRET_HASH = "tL0O+PSs4fz6RC7d+1+eVR2q1ZvrJM5ScY0Na/iGKdo=";
    private static final String TOTP = "TOTP";
    private static final String ACCESS_TOKEN = "TOKEN";

    private CognitoSingleStepLoginManager client;

    @Mock
    private Configuration config;
    @Mock
    private AWSCognitoIdentityProvider cognitoProvider;

    @Test
    public void loginShouldReturnNullWhenUserNotFound() {
        when(cognitoProvider.initiateAuth(any())).thenThrow(UserNotFoundException.class);

        assertThat(client.login(USERNAME, PASSWORD, TOTP))
            .isEmpty();
    }

    @Test
    public void loginShouldReturnNullWhenPasswordIsIncorrect() {
        when(cognitoProvider.initiateAuth(any())).thenThrow(NotAuthorizedException.class);

        assertThat(client.login(USERNAME, PASSWORD, TOTP))
            .isEmpty();
    }

    @Test
    public void loginShouldThrowInvalidUserStateIfNotConfigured() {
        InitiateAuthResult auth = mock(InitiateAuthResult.class);
        when(cognitoProvider.initiateAuth(any())).thenReturn(auth);
        when(auth.getChallengeName()).thenReturn("MFA_SETUP");

        assertThrows(InvalidCognitoUserStateException.class, () -> client.login(USERNAME, PASSWORD, TOTP));
    }

    @Test
    public void loginShouldReturnNullWhenTOTPIsIncorrect() {
        when(cognitoProvider.respondToAuthChallenge(any())).thenThrow(CodeMismatchException.class);

        assertThat(client.login(USERNAME, PASSWORD, TOTP))
            .isEmpty();
    }


    @Test
    public void loginShouldReturnCognitoUserRequest() {
        assertThat(client.login(USERNAME, PASSWORD, TOTP))
            .isNotEmpty();
    }

    @BeforeEach
    public void setupConfig() {
        client = new CognitoSingleStepLoginManager(COGNITO_POOL_ID, COGNITO_CLIENT_ID, APP_SECRET, cognitoProvider);
    }

    @BeforeEach
    public void setupCognitoProvier() {
        InitiateAuthResult initAuthResponse = mock(InitiateAuthResult.class);
        lenient().when(initAuthResponse.getChallengeName()).thenReturn("SOFTWARE_TOKEN_MFA");

        lenient().when(cognitoProvider.initiateAuth(argThat(request -> {
            if (request == null) {
                return false;
            }
            assertThat(request.getClientId()).isEqualTo(COGNITO_CLIENT_ID);
            assertThat(request.getAuthParameters().get("USERNAME")).isEqualTo(USERNAME);
            assertThat(request.getAuthParameters().get("PASSWORD")).isEqualTo(PASSWORD);
            assertThat(request.getAuthParameters().get("SECRET_HASH")).isEqualTo(SECRET_HASH);
            return true;
        }))).thenReturn(initAuthResponse);

        RespondToAuthChallengeResult responseToChallengeResult = mock(RespondToAuthChallengeResult.class);
        lenient().when(responseToChallengeResult.getChallengeName()).thenReturn(null);
        AuthenticationResultType authenticationResult = mock(AuthenticationResultType.class);
        lenient().when(responseToChallengeResult.getAuthenticationResult()).thenReturn(authenticationResult);
        lenient().when(authenticationResult.getAccessToken()).thenReturn(ACCESS_TOKEN);
        lenient().when(cognitoProvider.respondToAuthChallenge(argThat(request -> {
            if (request == null) {
                return false;
            }
            assertThat(request.getClientId()).isEqualTo(COGNITO_CLIENT_ID);
            assertThat(request.getChallengeName()).isEqualTo("SOFTWARE_TOKEN_MFA");
            assertThat(request.getChallengeResponses().get("USERNAME")).isEqualTo(USERNAME);
            assertThat(request.getChallengeResponses().get("SOFTWARE_TOKEN_MFA_CODE")).isEqualTo(TOTP);
            return true;
        }))).thenReturn(responseToChallengeResult);

        GetUserResult getUserResult = mock(GetUserResult.class);
        lenient().when(getUserResult.getUsername()).thenReturn(USERNAME);
        lenient().when(cognitoProvider.getUser(argThat(request -> {
            if (request == null) {
                return false;
            }
            assertThat(request.getAccessToken()).isEqualTo(ACCESS_TOKEN);
            return true;
        }))).thenReturn(getUserResult);
    }
}
