package cd.go.authorization.cognitomfasinglestep;

import cd.go.authorization.cognitomfasinglestep.executor.IsValidUserRequestExecutor;
import cd.go.authorization.cognitomfasinglestep.executor.RoleConfigValidateRequestExecutor;
import cd.go.authorization.cognitomfasinglestep.executor.UserAuthenticationExecutor;
import com.thoughtworks.go.plugin.api.exceptions.UnhandledRequestTypeException;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CognitoMFASingleStepPluginTest {
    private final CognitoMFASingleStepPlugin plugin = new CognitoMFASingleStepPlugin();

    @Mock
    private GoPluginApiResponse answer;

    @Mock
    private GoPluginApiRequest request;

    @Test
    public void it_should_authenticate_an_user() throws UnhandledRequestTypeException {
        try (MockedConstruction<UserAuthenticationExecutor> mocked = mockConstruction(UserAuthenticationExecutor.class, this::setupExecutor)) {
            when(request.requestName()).thenReturn("go.cd.authorization.authenticate-user");

            assertThat(plugin.handle(request))
                .isEqualTo(answer);
        }
    }

    @Test
    public void it_should_validate_an_user() throws UnhandledRequestTypeException {
        try (MockedConstruction<IsValidUserRequestExecutor> mocked = mockConstruction(IsValidUserRequestExecutor.class, this::setupExecutor)) {
            when(request.requestName()).thenReturn("go.cd.authorization.is-valid-user");

            assertThat(plugin.handle(request))
                .isEqualTo(answer);
        }
    }

    @Test
    public void it_should_validate_a_role_config() throws UnhandledRequestTypeException {
        try (MockedConstruction<RoleConfigValidateRequestExecutor> mocked = mockConstruction(RoleConfigValidateRequestExecutor.class, this::setupExecutor)) {
            when(request.requestName()).thenReturn("go.cd.authorization.role-config.validate");

            assertThat(plugin.handle(request))
                .isEqualTo(answer);
        }
    }

    private void setupExecutor(UserAuthenticationExecutor mock, MockedConstruction.Context context) throws Exception {
        when(mock.execute()).thenReturn(answer);
    }

    private void setupExecutor(IsValidUserRequestExecutor mock, MockedConstruction.Context context) {
        when(mock.execute()).thenReturn(answer);
    }

    private void setupExecutor(RoleConfigValidateRequestExecutor mock, MockedConstruction.Context context) throws Exception {
        when(mock.execute()).thenReturn(answer);
    }
}