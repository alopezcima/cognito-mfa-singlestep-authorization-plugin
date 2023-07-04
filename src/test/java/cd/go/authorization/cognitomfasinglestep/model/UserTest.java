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
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class UserTest {
    @Test
    public void shouldDefaultToNullWhenNoAttributes() {
        GetUserResult cognitouser = new GetUserResult();
        cognitouser.setUsername("USERNAME");

        User gocduser = new User(cognitouser);
        assertThat(gocduser.getUsername())
            .isEqualTo("USERNAME");

    }

    @Test
    public void shouldThrowIfNoUsername() {
        GetUserResult cognitouser = new GetUserResult();
        assertThrows(InvalidUsernameException.class, () -> new User(cognitouser));
    }

    @Test
    public void shouldPopulateAttributes() {
        GetUserResult cognitouser = new GetUserResult();
        List<AttributeType> attrs = new ArrayList<AttributeType>();

        cognitouser.setUsername("USERNAME");

        AttributeType emailId = new AttributeType();
        emailId.setName("email");
        emailId.setValue("EMAIL");
        attrs.add(emailId);


        AttributeType displayName = new AttributeType();
        displayName.setName("preferred_username");
        displayName.setValue("DISPLAY_NAME");
        attrs.add(displayName);


        cognitouser.setUserAttributes(attrs);

        User gocduser = new User(cognitouser);

        assertThat(gocduser.getDisplayName())
            .isEqualTo("DISPLAY_NAME");
        assertThat(gocduser.getEmailId())
            .isEqualTo("EMAIL");
    }
}
