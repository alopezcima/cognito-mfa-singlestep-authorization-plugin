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

import cd.go.authorization.cognitomfasinglestep.exception.InvalidCognitoUserCredentialsException;
import cd.go.authorization.cognitomfasinglestep.exception.InvalidCognitoUserStateException;
import cd.go.authorization.cognitomfasinglestep.model.User;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;

import static cd.go.authorization.cognitomfasinglestep.CognitoMFASingleStepPlugin.LOG;

public class CognitoSingleStepLoginManager {
    private final AWSCognitoIdentityProvider cognitoIDPClient;
    private final String cognitoClientId;
    private final String userPoolId;
    private final String appSecret;

    public CognitoSingleStepLoginManager(String userPoolId, String clientId, String appSecret, String regionName, String executionRole) {
        this(userPoolId, clientId, appSecret, getCognitoClientIDP(createCredentialsProvider(executionRole, regionName), regionName));
    }

    CognitoSingleStepLoginManager(String userPoolId, String clientId, String appSecret, AWSCognitoIdentityProvider cognitoIDPClient) {
        this.userPoolId = userPoolId;
        this.cognitoClientId = clientId;
        this.appSecret = appSecret;
        this.cognitoIDPClient = cognitoIDPClient;
    }

    private static AWSCredentialsProvider createCredentialsProvider(String role, String regionName) {
        if (role == null) {
            return new DefaultAWSCredentialsProviderChain();
        }
        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard().withRegion(regionName).build();

        return new STSAssumeRoleSessionCredentialsProvider.Builder(role, "gocd-cognito-auth-" + UUID.randomUUID())
            .withStsClient(stsClient)
            .build();
    }

    private static AWSCognitoIdentityProvider getCognitoClientIDP(AWSCredentialsProvider credentialsProvider, String regionName) {
        return AWSCognitoIdentityProviderClientBuilder.standard().withRegion(regionName).withCredentials(credentialsProvider).build();
    }

    public Optional<User> login(String user, String password, String totp) {
        // NOTE: This try-catch block shouldn't be split.
        // To ensure we comply with PCI information disclosure policy this block erase the information about which of
        // the steps taken in the authentication process actually fails.
        try {
            InitiateAuthResult auth = startAuth(user, password);
            if (!auth.getChallengeName().equals(ChallengeNameType.SOFTWARE_TOKEN_MFA.name())) {
                throw new InvalidCognitoUserStateException("Invalid challenge type: " + auth.getChallengeName());
            }
            RespondToAuthChallengeResult login = finishAuth(auth.getSession(), user, totp);
            if (login.getChallengeName() != null) {
                throw new InvalidCognitoUserStateException("Unexpected challenge: " + auth.getChallengeName());
            }
            GetUserRequest userRequest = new GetUserRequest();
            userRequest.setAccessToken(login.getAuthenticationResult().getAccessToken());
            LOG.info("Cognito authentication succeeded for user: " + user);
            return Optional.of(new User(cognitoIDPClient.getUser(userRequest)));
        } catch (InvalidCognitoUserCredentialsException e) {
            LOG.error("Cognito authentication failed for user: " + user);
            return Optional.empty();
        }
    }

    public boolean isValidUser(String user) {
        try {
            AdminGetUserRequest request = new AdminGetUserRequest()
                .withUsername(user)
                .withUserPoolId(this.userPoolId);
            AdminGetUserResult adminGetUserResult = cognitoIDPClient.adminGetUser(request);
            return adminGetUserResult.isEnabled();
        } catch (Exception e) {
            return false;
        }
    }

    private InitiateAuthResult startAuth(String user, String password) {
        InitiateAuthRequest authRequest = new InitiateAuthRequest();
        authRequest.setAuthFlow("USER_PASSWORD_AUTH");
        authRequest.setClientId(cognitoClientId);
        authRequest.addAuthParametersEntry("USERNAME", user);
        authRequest.addAuthParametersEntry("PASSWORD", password);
        String secretHash = this.calculateSecretHash(user);
        authRequest.addAuthParametersEntry("SECRET_HASH", secretHash);

        try {
            return cognitoIDPClient.initiateAuth(authRequest);
        } catch (UserNotFoundException | NotAuthorizedException e) {
            throw new InvalidCognitoUserCredentialsException("Invalid user or password");
        }
    }

    private String calculateSecretHash(String userName) {
        SecretKeySpec signingKey = new SecretKeySpec(
            appSecret.getBytes(StandardCharsets.UTF_8),
            "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);
            mac.update(userName.getBytes(StandardCharsets.UTF_8));
            byte[] rawHmac = mac.doFinal(cognitoClientId.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeAsString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating ");
        }
    }

    private RespondToAuthChallengeResult finishAuth(String session, String user, String totp) {
        RespondToAuthChallengeRequest challengeRequest = new RespondToAuthChallengeRequest();
        challengeRequest.setChallengeName(ChallengeNameType.SOFTWARE_TOKEN_MFA);
        challengeRequest.setSession(session);
        challengeRequest.setClientId(cognitoClientId);
        challengeRequest.addChallengeResponsesEntry("USERNAME", user);
        challengeRequest.addChallengeResponsesEntry("SECRET_HASH", this.calculateSecretHash(user));
        challengeRequest.addChallengeResponsesEntry("SOFTWARE_TOKEN_MFA_CODE", totp);

        try {
            return cognitoIDPClient.respondToAuthChallenge(challengeRequest);
        } catch (CodeMismatchException e) {
            throw new InvalidCognitoUserCredentialsException("Invalid TOTP");
        }
    }
}
