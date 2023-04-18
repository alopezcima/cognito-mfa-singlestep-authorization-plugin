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

package cd.go.authorization.cognitomfasinglestep;

import cd.go.authorization.cognitomfasinglestep.cognito.CognitoSingleStepLoginManager;
import cd.go.authorization.cognitomfasinglestep.exception.InvalidCognitoUserStateException;
import cd.go.authorization.cognitomfasinglestep.model.Configuration;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CognitoSingleStepLoginManagerTest {
    private static final String REGION = "eu-west-1";
    private static final String COGNITO_CLIENT_ID = "clientid";
    private static final String USERNAME = "USER";
    private static final String PASSWORD = "PASS";
    private static final String TOTP = "TOTP";
    private static final String ACCESS_TOKEN = "TOKEN";


    @Mock
    private Configuration config;
    @Mock
    private AWSCognitoIdentityProvider cognitoProvider;

    @Test
    public void loginShouldReturnNullWhenUserNotFound() {
        when(cognitoProvider.initiateAuth(any())).thenThrow(UserNotFoundException.class);

        CognitoSingleStepLoginManager client = new CognitoSingleStepLoginManager(config);

        assertNull(client.login(USERNAME, PASSWORD, TOTP));
    }

    @Test
    public void loginShouldReturnNullWhenPasswordIsIncorrect() {
        when(cognitoProvider.initiateAuth(any())).thenThrow(NotAuthorizedException.class);

        CognitoSingleStepLoginManager client = new CognitoSingleStepLoginManager(config);

        assertNull(client.login(USERNAME, PASSWORD, TOTP));
    }

    @Test(expected = InvalidCognitoUserStateException.class)
    public void loginShouldThrowInvalidUserStateIfNotConfigured() {
        InitiateAuthResult auth = mock(InitiateAuthResult.class);
        when(cognitoProvider.initiateAuth(any())).thenReturn(auth);
        when(auth.getChallengeName()).thenReturn("MFA_SETUP");

        CognitoSingleStepLoginManager client = new CognitoSingleStepLoginManager(config);

        client.login(USERNAME, PASSWORD, TOTP);
    }

    @Test
    public void loginShouldReturnNullWhenTOTPIsIncorrect() {
        when(cognitoProvider.respondToAuthChallenge(any())).thenThrow(CodeMismatchException.class);

        CognitoSingleStepLoginManager client = new CognitoSingleStepLoginManager(config);

        assertNull(client.login(USERNAME, PASSWORD, TOTP));
    }


    @Test
    public void loginShouldReturnCognitoUserRequest() {
        CognitoSingleStepLoginManager client = new CognitoSingleStepLoginManager(config);

        assertNotNull(client.login(USERNAME, PASSWORD, TOTP));
    }

    @Before
    public void setupConfig() {
        when(config.getClientId()).thenReturn(COGNITO_CLIENT_ID);
        when(config.getCognitoIDPProvider()).thenReturn(cognitoProvider);
    }

    @Before
    public void setupCognitoProvier() {
        InitiateAuthResult initAuthResponse = mock(InitiateAuthResult.class);
        when(initAuthResponse.getChallengeName()).thenReturn("SOFTWARE_TOKEN_MFA");

        when(cognitoProvider.initiateAuth(argThat(request -> {
            if (request == null) {
                return false;
            }
            assertEquals(request.getClientId(), COGNITO_CLIENT_ID);
            assertEquals(request.getAuthParameters().get("USERNAME"), USERNAME);
            assertEquals(request.getAuthParameters().get("PASSWORD"), PASSWORD);
            return true;
        }))).thenReturn(initAuthResponse);

        RespondToAuthChallengeResult responseToChallengeResult = mock(RespondToAuthChallengeResult.class);
        when(responseToChallengeResult.getChallengeName()).thenReturn(null);
        AuthenticationResultType authenticationResult = mock(AuthenticationResultType.class);
        when(responseToChallengeResult.getAuthenticationResult()).thenReturn(authenticationResult);
        when(authenticationResult.getAccessToken()).thenReturn(ACCESS_TOKEN);
        when(cognitoProvider.respondToAuthChallenge(argThat(request -> {
            if (request == null) {
                return false;
            }
            assertEquals(request.getClientId(), COGNITO_CLIENT_ID);
            assertEquals(request.getChallengeName(), "SOFTWARE_TOKEN_MFA");
            assertEquals(request.getChallengeResponses().get("USERNAME"), USERNAME);
            assertEquals(request.getChallengeResponses().get("SOFTWARE_TOKEN_MFA_CODE"), TOTP);
            return true;
        }))).thenReturn(responseToChallengeResult);

        GetUserResult getUserResult = mock(GetUserResult.class);
        when(getUserResult.getUsername()).thenReturn(USERNAME);
        when(cognitoProvider.getUser(argThat(request -> {
            if (request == null) {
                return false;
            }
            assertEquals(request.getAccessToken(), ACCESS_TOKEN);
            return true;
        }))).thenReturn(getUserResult);
    }
}
