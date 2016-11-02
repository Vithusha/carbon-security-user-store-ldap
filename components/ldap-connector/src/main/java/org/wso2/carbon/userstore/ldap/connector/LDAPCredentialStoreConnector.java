/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.userstore.ldap.connector;

import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;

import javax.security.auth.callback.Callback;

/**
 * LDAP based implementation for credential store connector.
 */
public class LDAPCredentialStoreConnector implements CredentialStoreConnector {

    @Override
    public void init(String s, CredentialStoreConfig credentialStoreConfig) throws CredentialStoreException {
    }

    @Override
    public String getCredentialStoreId() {
        return null;
    }

    @Override
    public User.UserBuilder authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure {
        return null;
    }

    @Override
    public boolean canHandle(Callback[] callbacks) {
        return false;
    }

    @Override
    public CredentialStoreConfig getCredentialStoreConfig() {
        return null;
    }
}
