package cd.go.authorization.cognitomfasinglestep.executor;

import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;

import java.util.Map;

import static cd.go.authorization.cognitomfasinglestep.utils.Util.GSON;
import static com.thoughtworks.go.plugin.api.response.DefaultGoApiResponse.SUCCESS_RESPONSE_CODE;
import static java.lang.Boolean.TRUE;
import static java.lang.Boolean.FALSE;

public class GetConfigurationPropertiesExecutor {
    public GoPluginApiResponse execute() {
        Map<String, Object> userMap = Map.of(
            "UserPoolId", Map.of(
                "required", TRUE,
                "display-name", "User Pool ID",
                "display-order", "0"
            ),
            "RegionName", Map.of(
                "required", TRUE,
                "display-name", "User Pool region",
                "display-order", "1"
            ),
            "ClientId", Map.of(
                "required", TRUE,
                "display-name", "User Pool app client ID",
                "display-order", "2"
            ),
            "AppSecret", Map.of(
                "required", TRUE,
                "display-name", "User Pool app client secret",
                "display-order", "3"
            ),
            "ExecutionRoleARN", Map.of(
                "required", FALSE,
                "display-name", "Role used when using Cognito",
                "display-order", "4"
            )
        );

        return new DefaultGoPluginApiResponse(SUCCESS_RESPONSE_CODE, GSON.toJson(userMap));
    }
}