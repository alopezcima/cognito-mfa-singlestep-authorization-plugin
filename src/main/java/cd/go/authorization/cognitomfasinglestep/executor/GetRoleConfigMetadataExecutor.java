package cd.go.authorization.cognitomfasinglestep.executor;

import cd.go.authorization.cognitomfasinglestep.annotation.MetadataHelper;
import cd.go.authorization.cognitomfasinglestep.annotation.ProfileMetadata;
import cd.go.authorization.cognitomfasinglestep.model.RoleConfiguration;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;

import java.util.List;

import static cd.go.authorization.cognitomfasinglestep.utils.Util.GSON;

public class GetRoleConfigMetadataExecutor {
    public GetRoleConfigMetadataExecutor(GoPluginApiRequest request) {
    }

    public GoPluginApiResponse execute() {
        final List<ProfileMetadata> authConfigMetadata = MetadataHelper.getMetadata(RoleConfiguration.class);
        String json = GSON.toJson(authConfigMetadata);
        return new DefaultGoPluginApiResponse(200, json);
    }
}
