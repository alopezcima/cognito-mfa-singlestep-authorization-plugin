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
import cd.go.authorization.cognitomfasinglestep.model.AuthenticationResponse;
import cd.go.authorization.cognitomfasinglestep.model.User;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static org.assertj.core.api.Assertions.as;
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
    private static final String ID_TOKEN = "header.eyJzdWIiOiIwYTI3NWM4Zi0xYzNjLTRiOGItYWI3NS04YTk3MjNiMzhlYzkiLCJjb2duaXRvOmdyb3VwcyI6WyJhZG1pbiIsInRlc3RlciJdLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS13ZXN0LTEuYW1hem9uYXdzLmNvbS9wb29sSWQiLCJjb2duaXRvOnVzZXJuYW1lIjoiMGEyNzVjOGYtMWMzYy00YjhiLWFiNzUtOGE5NzIzYjM4ZWM5Iiwib3JpZ2luX2p0aSI6IjdhYTRkYmFkLTFmMTktNGU3NC1iMzI2LTlhN2QwZTg4MmQ1NSIsImF1ZCI6ImNsaWVudGlkIiwiZXZlbnRfaWQiOiJlODJkNmJhMC00MDE0LTRjYjAtYTAwMi01YzY2NzY3Y2I1MTMiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY4ODk4MjQyNCwiZXhwIjoxNjg4OTg2MDI0LCJpYXQiOjE2ODg5ODI0MjQsImp0aSI6IjM5YWE5Njc3LTI4ZjQtNDkzYi04OWUyLTdiZTA1YzYzNzAxNCIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSJ9.signature";

    private CognitoSingleStepLoginManager client;

    @Mock
    private AWSCognitoIdentityProvider cognitoProvider;

    @Mock
    private InitiateAuthResult initAuthResponse;

    @Mock
    private RespondToAuthChallengeResult responseToChallengeResult;

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
        when(cognitoProvider.initiateAuth(any())).thenReturn(initAuthResponse);
        when(initAuthResponse.getChallengeName()).thenReturn("MFA_SETUP");

        assertThrows(InvalidCognitoUserStateException.class, () -> client.login(USERNAME, PASSWORD, TOTP));
    }

    @Test
    public void loginShouldReturnNullWhenTOTPIsIncorrect() {
        when(cognitoProvider.respondToAuthChallenge(any())).thenThrow(CodeMismatchException.class);

        assertThat(client.login(USERNAME, PASSWORD, TOTP))
            .isEmpty();
    }


    @Test
    public void loginShouldReturnWithTheUsername() {
        assertThat(client.login(USERNAME, PASSWORD, TOTP))
            .isNotEmpty()
            .get()
            .extracting(AuthenticationResponse::getUser)
            .extracting(User::getUsername)
            .isEqualTo(USERNAME);
    }

    @Test
    public void loginShouldReturnWithTheUserRoles() {
        UserRolePredicate testerRolePredicate = mock(UserRolePredicate.class);
        when(testerRolePredicate.getRole()).thenReturn("user-role-tester");
        when(testerRolePredicate.test("admin")).thenReturn(FALSE);
        when(testerRolePredicate.test("tester")).thenReturn(TRUE);
        client = new CognitoSingleStepLoginManager(COGNITO_POOL_ID, COGNITO_CLIENT_ID, APP_SECRET, List.of(testerRolePredicate), cognitoProvider);
        assertThat(client.login(USERNAME, PASSWORD, TOTP))
            .isNotEmpty()
            .get()
            .extracting(AuthenticationResponse::getRoles, as(InstanceOfAssertFactories.COLLECTION))
            .containsExactlyInAnyOrder("user-role-tester");
    }

    @Test
    public void itShouldNotUsedSecretHashWhenTheApplicationSecretIsNotSet() {
        client = new CognitoSingleStepLoginManager(COGNITO_POOL_ID, COGNITO_CLIENT_ID, null, List.of(), cognitoProvider);
        when(cognitoProvider.initiateAuth(argThat(request -> {
            if (request == null) {
                return false;
            }
            assertThat(request.getClientId()).isEqualTo(COGNITO_CLIENT_ID);
            assertThat(request.getAuthParameters().get("USERNAME")).isEqualTo(USERNAME);
            assertThat(request.getAuthParameters().get("PASSWORD")).isEqualTo(PASSWORD);
            assertThat(request.getAuthParameters().get("SECRET_HASH")).isNull();
            return true;
        }))).thenReturn(initAuthResponse);
        when(cognitoProvider.respondToAuthChallenge(argThat(request -> {
            if (request == null) {
                return false;
            }
            assertThat(request.getClientId()).isEqualTo(COGNITO_CLIENT_ID);
            assertThat(request.getChallengeName()).isEqualTo("SOFTWARE_TOKEN_MFA");
            assertThat(request.getChallengeResponses().get("USERNAME")).isEqualTo(USERNAME);
            assertThat(request.getChallengeResponses().get("SECRET_HASH")).isNull();
            assertThat(request.getChallengeResponses().get("SOFTWARE_TOKEN_MFA_CODE")).isEqualTo(TOTP);
            return true;
        }))).thenReturn(responseToChallengeResult);

        assertThat(client.login(USERNAME, PASSWORD, TOTP))
            .isNotEmpty()
            .get()
            .matches(response -> response.getUser().getUsername().equals(USERNAME));
    }

    @BeforeEach
    public void setupConfig() {
        client = new CognitoSingleStepLoginManager(COGNITO_POOL_ID, COGNITO_CLIENT_ID, APP_SECRET, List.of(), cognitoProvider);
    }

    @BeforeEach
    public void setupCognitoProvier() {
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

        lenient().when(responseToChallengeResult.getChallengeName()).thenReturn(null);
        AuthenticationResultType authenticationResult = mock(AuthenticationResultType.class);
        lenient().when(responseToChallengeResult.getAuthenticationResult()).thenReturn(authenticationResult);
        lenient().when(authenticationResult.getAccessToken()).thenReturn(ACCESS_TOKEN);
        lenient().when(authenticationResult.getIdToken()).thenReturn(ID_TOKEN);
        lenient().when(cognitoProvider.respondToAuthChallenge(argThat(request -> {
            if (request == null) {
                return false;
            }
            assertThat(request.getClientId()).isEqualTo(COGNITO_CLIENT_ID);
            assertThat(request.getChallengeName()).isEqualTo("SOFTWARE_TOKEN_MFA");
            assertThat(request.getChallengeResponses().get("USERNAME")).isEqualTo(USERNAME);
            assertThat(request.getChallengeResponses().get("SECRET_HASH")).isEqualTo(SECRET_HASH);
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
