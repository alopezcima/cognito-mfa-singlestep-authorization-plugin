package cd.go.authorization.cognitomfasinglestep;

import cd.go.authorization.cognitomfasinglestep.exception.InvalidCognitoUserStateException;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CognitoClientTest {
    @Test
    public void loginShouldReturnNullWhenUserNotFound() throws Exception {
        AWSCognitoIdentityProvider cognito = mock(AWSCognitoIdentityProvider.class);
        when(cognito.initiateAuth(any())).thenThrow(UserNotFoundException.class);

        CognitoClient client = new CognitoClient(cognito, "clientid");

        assertNull(client.login("USER", "PASS", "OTP"));
    }

    @Test
    public void loginShouldReturnNullWhenPasswordIsIncorrect() throws Exception {
        AWSCognitoIdentityProvider cognito = mock(AWSCognitoIdentityProvider.class);
        when(cognito.initiateAuth(any())).thenThrow(NotAuthorizedException.class);

        CognitoClient client = new CognitoClient(cognito, "clientid");

        assertNull(client.login("USER", "PASS", "OTP"));
    }

    @Test(expected = InvalidCognitoUserStateException.class)
    public void loginShouldThrowInvalidUserStateIfNotConfigured() throws Exception {
        AWSCognitoIdentityProvider cognito = mock(AWSCognitoIdentityProvider.class);
        InitiateAuthResult auth = mock(InitiateAuthResult.class);
        when(cognito.initiateAuth(any())).thenReturn(auth);
        when(auth.getChallengeName()).thenReturn("MFA_SETUP");

        CognitoClient client = new CognitoClient(cognito, "clientid");

        client.login("USER", "PASS", "OTP");
    }

    @Test
    public void loginShouldReturnNullWhenTOTPIsIncorrect() throws Exception {
        AWSCognitoIdentityProvider cognito = mock(AWSCognitoIdentityProvider.class);
        InitiateAuthResult auth = mock(InitiateAuthResult.class);
        when(cognito.initiateAuth(any())).thenReturn(auth);
        when(auth.getChallengeName()).thenReturn("SOFTWARE_TOKEN_MFA");
        when(cognito.respondToAuthChallenge(any())).thenThrow(CodeMismatchException.class);

        CognitoClient client = new CognitoClient(cognito, "clientid");

        assertNull(client.login("USER", "PASS", "OTP"));
    }


    @Test
    public void loginShouldReturnCognitoUserRequest() throws Exception {
        AWSCognitoIdentityProvider cognito = mock(AWSCognitoIdentityProvider.class);
        InitiateAuthResult auth = mock(InitiateAuthResult.class);
        RespondToAuthChallengeResult login = mock(RespondToAuthChallengeResult.class, RETURNS_DEEP_STUBS);
        GetUserResult user = new GetUserResult();

        when(cognito.initiateAuth(any())).thenReturn(auth);
        when(auth.getChallengeName()).thenReturn("SOFTWARE_TOKEN_MFA");
        when(cognito.respondToAuthChallenge(any())).thenReturn(login);
        when(login.getAuthenticationResult().getAccessToken()).thenReturn("TOKEN");
        when(cognito.getUser(any())).thenReturn(user);

        CognitoClient client = new CognitoClient(cognito, "clientid");

        assertSame(client.login("USER", "PASS", "OTP"), user);
    }

}
