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

package cd.go.authorization.cognitomfasinglestep.model;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.Collection;
import java.util.Collections;

import static cd.go.authorization.cognitomfasinglestep.utils.Util.GSON;

public class AuthenticationResponse {
    @Expose
    @SerializedName("user")
    private final User user;

    @Expose
    @SerializedName("roles")
    private final Collection<String> roles;

    public AuthenticationResponse(User user, Collection<String> roles) {
        this.user = user;
        this.roles = Collections.unmodifiableCollection(roles);
    }

    public User getUser() {
        return user;
    }

    public Collection<String> getRoles() {
        return roles;
    }

    public String toJson() {
        return GSON.toJson(this);
    }
}
