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

import cd.go.authorization.cognitomfasinglestep.exception.InvalidUsernameException;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.GetUserResult;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public class User {
    @Expose
    @SerializedName("username")
    private String username;

    @Expose
    @SerializedName("display_name")
    private String displayName;

    @Expose
    @SerializedName("email")
    private String emailId;

    public User(String username, String displayName, String emailId) {
        this.username = username;
        this.displayName = displayName;
        this.emailId = emailId == null ? null : emailId.toLowerCase().trim();

        if (this.username == null || this.username.isEmpty()) {
            throw new InvalidUsernameException("Username can not be blank.");
        }
    }

    public User(GetUserResult cognitouser) {
        this.displayName = null;
        this.emailId = null;

        List<AttributeType> attrs = cognitouser.getUserAttributes();
        if (attrs != null) {
            for (AttributeType attr : cognitouser.getUserAttributes()) {
                switch (attr.getName()) {
                    case "email":
                        this.emailId = attr.getValue();
                        break;
                    case "preferred_username":
                        this.displayName = attr.getValue();
                        break;
                }
            }
        }

        this.username = this.emailId == null ? cognitouser.getUsername() : this.emailId;

        if (this.username == null || this.username.isEmpty()) {
            throw new InvalidUsernameException("Username can not be blank.");
        }
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName != null && displayName.length() > 0 ? displayName : username;
    }

    public String getEmailId() {
        return emailId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        User user = (User) o;

        if (displayName != null ? !displayName.equals(user.displayName) : user.displayName != null) return false;
        if (emailId != null ? !emailId.equals(user.emailId) : user.emailId != null) return false;
        if (username != null ? !username.equals(user.username) : user.username != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (displayName != null ? displayName.hashCode() : 0);
        result = 31 * result + (emailId != null ? emailId.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return new StringBuilder("User@{username=").append(username)
            .append(", displayName=").append(displayName)
            .append(", emailId=").append(emailId)
            .append("}").toString();
    }
}
