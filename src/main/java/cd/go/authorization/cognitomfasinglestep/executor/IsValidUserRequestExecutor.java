package cd.go.authorization.cognitomfasinglestep.executor;

import cd.go.authorization.cognitomfasinglestep.command.Authenticator;
import cd.go.authorization.cognitomfasinglestep.model.IsValidUserRequest;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;

import static com.thoughtworks.go.plugin.api.response.DefaultGoApiResponse.SUCCESS_RESPONSE_CODE;
import static com.thoughtworks.go.plugin.api.response.DefaultGoApiResponse.VALIDATION_ERROR;

public class IsValidUserRequestExecutor implements RequestExecutor {
    private final IsValidUserRequest request;

    @Override
    public GoPluginApiResponse execute() {
        Authenticator authenticator = new Authenticator(request.getAuthConfig());

        boolean isValidUser = authenticator.existUser(request.getUsername());
        return new DefaultGoPluginApiResponse(isValidUser ? SUCCESS_RESPONSE_CODE : VALIDATION_ERROR);
    }

    public IsValidUserRequestExecutor(GoPluginApiRequest request) {
        this.request = IsValidUserRequest.fromJSON(request.requestBody());
    }
}
