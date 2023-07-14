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

import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static cd.go.authorization.cognitomfasinglestep.utils.Util.GSON;
import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class RoleConfigValidateRequestExecutorTest {
    @Mock
    private GoPluginApiRequest request;
    private RoleConfigValidateRequestExecutor executor;

    @BeforeEach
    public void setup() {
        this.executor = new RoleConfigValidateRequestExecutor(request);
    }

    @Test
    public void it_should_return_not_null() {
        when(request.requestBody()).thenReturn("");
        assertThat(executor.execute())
            .isNotNull();
    }

    @Test
    public void it_should_return_a_request_error_if_the_request_is_invalid() throws Exception {
        when(request.requestBody()).thenReturn("{\"field\":\"no-valid\"}");
        assertThat(executor.execute())
            .extracting(GoPluginApiResponse::responseCode)
            .isEqualTo(400);
    }

    @Test
    public void it_should_return_ok_with_a_valid_role_configuration() {
        when(request.requestBody()).thenReturn("{\"MemberOf\": \"tester\"}");
        GoPluginApiResponse response = executor.execute();
        assertThat(response)
            .extracting(GoPluginApiResponse::responseCode)
            .isEqualTo(200);
        assertThat(response)
            .extracting(GoPluginApiResponse::responseBody)
            .isEqualTo("[]");
    }
}
