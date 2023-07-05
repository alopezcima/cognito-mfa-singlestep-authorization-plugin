package cd.go.authorization.cognitomfasinglestep.executor;

import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;

public class GetRoleConfigMetadataExecutor {
    public GetRoleConfigMetadataExecutor(GoPluginApiRequest request) {
    }

    public GoPluginApiResponse execute() {
        return new DefaultGoPluginApiResponse(200, "[]");
    }
}
