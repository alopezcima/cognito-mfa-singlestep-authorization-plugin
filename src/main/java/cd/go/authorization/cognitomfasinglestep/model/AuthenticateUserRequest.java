package cd.go.authorization.cognitomfasinglestep.model;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.Collection;
import java.util.Objects;

import static cd.go.authorization.cognitomfasinglestep.utils.Util.GSON;

public class AuthenticateUserRequest {
    @Expose
    @SerializedName("auth_configs")
    private Collection<AuthConfig> authConfigs;

    @Expose
    @SerializedName("credentials")
    private Credentials credentials;

    public AuthenticateUserRequest() {
    }

    public AuthenticateUserRequest(Credentials credentials, Collection<AuthConfig> authConfigs) {
        this.authConfigs = authConfigs;
        this.credentials = credentials;
    }

    public Collection<AuthConfig> getAuthConfigs() {
        return authConfigs;
    }

    public Credentials getCredentials() {
        return credentials;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticateUserRequest that = (AuthenticateUserRequest) o;
        return Objects.equals(authConfigs, that.authConfigs) && Objects.equals(credentials, that.credentials);
    }

    @Override
    public int hashCode() {
        return Objects.hash(authConfigs, credentials);
    }

    public static AuthenticateUserRequest fromJSON(String requestBody) {
        return GSON.fromJson(requestBody, AuthenticateUserRequest.class);
    }
}
