package cd.go.authorization.cognitomfasinglestep;

import cd.go.authorization.cognitomfasinglestep.executor.IsValidUserRequestExecutor;
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

    private IsValidUserRequestExecutor executor;

    @Test
    public void it_should_validate_an_user() throws Exception {
        try (MockedConstruction<IsValidUserRequestExecutor> mocked = mockConstruction(IsValidUserRequestExecutor.class, this::setupExecutor)) {
            when(request.requestName()).thenReturn("go.cd.authorization.is-valid-user");

            assertThat(plugin.handle(request))
                .isEqualTo(answer);
        }
    }

    private void setupExecutor(IsValidUserRequestExecutor mock, MockedConstruction.Context context) {
        this.executor = mock;
        when(executor.execute()).thenReturn(answer);
    }
}