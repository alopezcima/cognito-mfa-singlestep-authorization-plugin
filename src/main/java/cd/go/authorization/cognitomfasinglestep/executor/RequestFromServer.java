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

package cd.go.authorization.cognitomfasinglestep.executor;

public enum RequestFromServer {

    REQUEST_GET_PLUGIN_ICON("go.cd.authorization.get-icon"),
    REQUEST_GET_CAPABILITIES("go.cd.authorization.get-capabilities"),
    REQUEST_GET_USER_ROLES("go.cd.authorization.get-user-roles"),
    IS_VALID_USER("go.cd.authorization.is-valid-user"),

    REQUEST_GET_AUTH_CONFIG_METADATA("go.cd.authorization.auth-config.get-metadata"),
    REQUEST_AUTH_CONFIG_VIEW("go.cd.authorization.auth-config.get-view"),
    REQUEST_VALIDATE_AUTH_CONFIG("go.cd.authorization.auth-config.validate"),
    REQUEST_VERIFY_CONNECTION("go.cd.authorization.auth-config.verify-connection"),

    REQUEST_GET_ROLE_CONFIG_METADATA("go.cd.authorization.role-config.get-metadata"),
    REQUEST_ROLE_CONFIG_VIEW("go.cd.authorization.role-config.get-view"),
    REQUEST_VALIDATE_ROLE_CONFIG("go.cd.authorization.role-config.validate"),

    REQUEST_AUTHENTICATE_USER("go.cd.authorization.authenticate-user"),
    REQUEST_SEARCH_USERS("go.cd.authorization.search-users"),

    REQUEST_FETCH_ACCESS_TOKEN("go.cd.authorization.fetch-access-token"),
    REQUEST_GET_CONFIGURATION("go.plugin-settings.get-configuration");

    private final String requestName;

    RequestFromServer(String requestName) {
        this.requestName = requestName;
    }

    public static RequestFromServer fromString(String requestName) {
        if (requestName != null) {
            for (RequestFromServer requestFromServer : RequestFromServer.values()) {
                if (requestName.equalsIgnoreCase(requestFromServer.requestName)) {
                    return requestFromServer;
                }
            }
        }

        throw new NoSuchRequestHandler("Request " + requestName + " is not supported by plugin.");
    }

    public String requestName() {
        return requestName;
    }
}

