package cd.go.authorization.cognitomfasinglestep.executor;

import cd.go.authorization.cognitomfasinglestep.command.Authenticator;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IsValidUserRequestExecutorTest {
    private IsValidUserRequestExecutor executor;

    private static final String USER = "aUser";

    @Mock
    private GoPluginApiRequest request;

    @Mock
    private Authenticator authenticator;


    @Test
    public void it_should_not_return_null() {
        try (MockedConstruction<Authenticator> mocked = mockConstruction(Authenticator.class, this::setupAcceptUser)) {
            assertThat(executor.execute())
                .isNotNull();
        }
    }

    @Test
    public void it_should_validate_a_user() {
        try (MockedConstruction<Authenticator> mocked = mockConstruction(Authenticator.class, this::setupAcceptUser)) {
            assertThat(executor.execute())
                .extracting(GoPluginApiResponse::responseCode)
                .isEqualTo(200);
        }
    }

    @Test
    public void it_should_reject_a_user() {
        try (MockedConstruction<Authenticator> mocked = mockConstruction(Authenticator.class, this::setupRejectUser)) {
            assertThat(executor.execute())
                .extracting(GoPluginApiResponse::responseCode)
                .isEqualTo(412);
        }
    }

    private void setupAcceptUser(Authenticator mock, MockedConstruction.Context context) {
        this.authenticator = mock;
        when(authenticator.existUser(USER)).thenReturn(TRUE);
    }

    private void setupRejectUser(Authenticator mock, MockedConstruction.Context context) {
        this.authenticator = mock;
        when(authenticator.existUser(USER)).thenReturn(FALSE);
    }

    @BeforeEach
    public void setup() {
        String requestBody = "{\n" +
            "  \"auth_config\": {\n" +
            "    \"configuration\": {\n" +
            "      \"ClientId\": \"clientId\",\n" +
            "      \"AppSecret\": \"appSecret\",\n" +
            "      \"UserPoolId\": \"userPoolId\",\n" +
            "      \"RegionName\": \"region\"\n" +
            "     }," +
            "    \"id\": \"cognito\"\n" +
            "  },\n" +
            "  \"username\": \"aUser\"\n" +
            "}";
        when(request.requestBody()).thenReturn(requestBody);
        executor = new IsValidUserRequestExecutor(request);
    }
}