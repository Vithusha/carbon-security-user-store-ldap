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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.identity.mgt.callback.IdentityCallback;
import org.wso2.carbon.identity.mgt.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreConnectorException;
import org.wso2.carbon.identity.mgt.store.connector.CredentialStoreConnector;
import org.wso2.carbon.identity.mgt.util.IdentityUserMgtUtil;
import org.wso2.carbon.userstore.ldap.datasource.utils.LDAPConstants;
import org.wso2.carbon.userstore.ldap.datasource.utils.LDAPConnectionContext;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;

/**
 * LDAP based implementation for credential store connector.
 */
public class LDAPCredentialStoreConnector implements CredentialStoreConnector {

    /*
    @Override
    public void init(String s, CredentialStoreConfig credentialStoreConfig) throws CredentialStoreException {
    }
    */


    private static Logger log = LoggerFactory.getLogger(LDAPCredentialStoreConnector.class);
    private Map<String, String> properties;
    private String credentialStoreId;
    private CredentialStoreConnectorConfig credentialStoreConfig;
    LDAPConnectionContext connectionSource;


    @Override
    public void init(CredentialStoreConnectorConfig credentialStoreConnectorConfig) throws CredentialStoreConnectorException {

        this.credentialStoreConfig = credentialStoreConnectorConfig;
        this.properties = credentialStoreConfig.getProperties();
        this.credentialStoreId = credentialStoreConnectorConfig.getConnectorId();
        // check if required configurations are in the user-mgt.xml

        try {
            connectionSource = new LDAPConnectionContext(properties);
        } catch (DataSourceException e) {
            throw  new  CredentialStoreConnectorException("Error occurred while initiating data source.",e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Initialization Started " + System.currentTimeMillis());
        }

    }

    @Override
    public String getCredentialStoreConnectorId() {
        return credentialStoreId;
    }

    @Override
    public void authenticate(String connectorUserId,Callback[] callbacks) throws AuthenticationFailure, CredentialStoreConnectorException {

        char[] password = null;
        String passWord;
        String principalname=connectorUserId+ LDAPConstants.AUTHENTICATE_PRINCIPAL_NAME;


        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        if ( password == null) {
            throw new AuthenticationFailure("Data required for authentication is missing.");
        }
        passWord = new String(password);
        try {
            connectionSource.getContextWithCredentials(principalname, passWord);
        } catch (CredentialStoreConnectorException e) {
            throw new CredentialStoreConnectorException("Invalid Username or password" + e);
        }


    }

    @Override
    public boolean canHandle(Callback[] callbacks) {
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                return true;
            }
        }

        return false;
    }
    @Override
    public boolean canStore(Callback[] callbacks) {
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                return true;
            }
        }

        return false;
    }

    @Override
    public CredentialStoreConnectorConfig getCredentialStoreConfig() {
        return credentialStoreConfig;
    }

    @Override
    public String addCredential(List<Callback> list) throws CredentialStoreConnectorException {
        return null;
    }





    @Override
    public Map<String, String> addCredentials(Map<String, List<Callback>> map) throws CredentialStoreConnectorException {
        return null;
    }

    @Override
    public String updateCredentials(String username, List<Callback> callbacks) throws CredentialStoreConnectorException {
        char[] password = null;
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        try {
            updateCredential(username, password);
        } catch (UnsupportedEncodingException|NamingException e) {
            throw  new CredentialStoreConnectorException("Error occured while updationg the Credentials" + e);
        }
        return username;
    }

    @Override
    public String updateCredentials(String s, List<Callback> list, List<Callback> list1) throws CredentialStoreConnectorException {
        return null;
    }




    @Override
    public void deleteCredential(String s) throws CredentialStoreConnectorException {
        throw new CredentialStoreConnectorException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }



    private int getKeyLength() {
        int keyLength;
        String keyLengthObj = credentialStoreConfig.getProperties().get(LDAPConstants.KEY_LENGTH);
        if (keyLengthObj != null) {
            keyLength = Integer.parseInt(keyLengthObj);
        } else {
            keyLength = 256;
        }
        return keyLength;
    }

    private int getIterationCount() {
        int iterationCount;
        String iterationCountObj = credentialStoreConfig.getProperties().get(LDAPConstants.ITERATION_COUNT);
        if (iterationCountObj != null) {
            iterationCount = Integer.parseInt(iterationCountObj);
        } else {
            iterationCount = 4096;
        }
        return iterationCount;
    }

    private String getHashAlgo() {
        String hashAlgo;
        hashAlgo = credentialStoreConfig.getProperties().get(LDAPConstants.HASH_ALGO);
        if (hashAlgo == null) {
            hashAlgo = "SHA256";
        }
        return hashAlgo;
    }
private void changePASSWORD(DirContext ctx,String name,String password) throws NamingException {


    String entry = "ldap://localhost:389/" + name;

    Attributes pass = ctx.getAttributes(entry, new String[]{"userPassword"
    });


    ModificationItem[] mods = new ModificationItem[1];
    mods[0] = new ModificationItem(ctx.REPLACE_ATTRIBUTE, new BasicAttribute("userPassword", password));

    ctx.modifyAttributes(entry, mods);
}

private void updateCredential(String userName,char[] newPassword) throws UnsupportedEncodingException, NamingException, CredentialStoreConnectorException {
    //set password is a ldap modfy operation
    DirContext context=connectionSource.getContext();
    ModificationItem[] mods = new ModificationItem[1];

    //Replace the "unicdodePwd" attribute with a new value
    //Password must be both Unicode and a quoted string
    String newQuotedPassword = "\"" + newPassword + "\"";
    byte[] newUnicodePassword = newQuotedPassword.getBytes("UTF-16LE");


    mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("unicodePwd", newUnicodePassword));

    // Perform the update
    context.modifyAttributes(userName + LDAPConstants.USER_SEARCH_BASE, mods);
    System.out.println(userName + " " + mods);

    System.out.println("Reset Password for: " + userName);


}


private void addCredential(String username, char[] password )
{

}


    public void addCredential(String username, Callback[] callbacks) throws CredentialStoreConnectorException {
        char[] password = null;
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        if (password == null) {
            throw new CredentialStoreConnectorException("Data required for authentication is missing.");
        }
        addCredential(username, password);
    }

    public String addCredential(Callback[] callbacks) throws CredentialStoreConnectorException {
        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                if (password == null) {
                    password = ((PasswordCallback) callback).getPassword();
                } else {
                    throw new CredentialStoreConnectorException("Multiple passwords found");
                }
            }
        }

        String username = IdentityUserMgtUtil.generateUUID();

        addCredential(username, password);
        return username;
    }

    public void updateCredential(Callback[] callbacks) throws CredentialStoreConnectorException {
        Map<String, String> userData = null;
        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof IdentityCallback) {
                userData = (Map<String, String>) ((IdentityCallback) callback).getContent();
            } else if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        if (userData == null || userData.get(LDAPConstants.USER_ID) == null) {
            throw new CredentialStoreConnectorException("No enough data to update the credential");
        }
        try {
            updateCredential(userData.get(LDAPConstants.USER_ID),password);
        } catch (UnsupportedEncodingException e) {
            throw  new CredentialStoreConnectorException("Error occured while updating the credential" ,e);
        } catch (NamingException e) {
            throw  new CredentialStoreConnectorException("Error occured while updating the credential" ,e);
        }
    }


    public void updateCredential(String username, Callback[] callbacks) throws CredentialStoreConnectorException {
        char[] password = null;
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        try {
            updateCredential(username, password);
        } catch (UnsupportedEncodingException e) {
            throw  new CredentialStoreConnectorException("Error occured while updating the credential" ,e);
        } catch (NamingException e) {
            throw  new CredentialStoreConnectorException("Error occured while updating the credential" ,e);
        }
    }

}

