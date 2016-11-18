package org.wso2.carbon.security.userstore.ldap.test.osgi.connector;

import com.google.inject.Inject;
import org.junit.Assert;
import org.ops4j.pax.exam.util.Filter;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.mgt.IdentityCallback;
import org.wso2.carbon.identity.mgt.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.constant.UserCoreConstants;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.store.connector.CredentialStoreConnector;
import org.wso2.carbon.identity.mgt.store.connector.CredentialStoreConnectorFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Created by wso2 on 11/8/16.
 */
public class LDAPCredentialConnectorTest extends LDAPIdentityConnectorTests{

    @Inject
    @Filter("(connector-type=JDBCCredentialStore)")
    protected CredentialStoreConnectorFactory credentialStoreConnectorFactory;

    private static CredentialStoreConnector credentialStoreConnector;


    private void initConnector() throws CredentialStoreException {
        Assert.assertNotNull(credentialStoreConnectorFactory);
        credentialStoreConnector = credentialStoreConnectorFactory.getInstance();

        CredentialStoreConnectorConfig credentialStoreConnectorConfig = new CredentialStoreConnectorConfig();
        credentialStoreConnectorConfig.setConnectorId("JDBCCS1");
        credentialStoreConnectorConfig.setConnectorType("JDBCCredentialStore");
        credentialStoreConnectorConfig.setDomainName("carbon");
        credentialStoreConnectorConfig.setPrimaryAttribute("username");

        Properties properties = new Properties();
        properties.setProperty("dataSource", "WSO2_CARBON_DB");
        properties.setProperty("hashAlgorithm", "SHA256");
        properties.setProperty("databaseType", "MySQL");
        credentialStoreConnectorConfig.setProperties(properties);
        credentialStoreConnector.init(credentialStoreConnectorConfig);
    }

    @Test(priority = 1)
    public void testAuthentication() throws CredentialStoreException, IdentityStoreException, AuthenticationFailure {

        //As beforeClass is not supported, connector is initialized here
        initConnector();
        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        IdentityCallback<Map> carbonCallback = new IdentityCallback<>(null);

        Map<String, String> userData = new HashMap<>();
        userData.put(UserCoreConstants.USER_ID, "admin");
        carbonCallback.setContent(userData);

        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});

        callbacks[0] = passwordCallback;
        callbacks[1] = carbonCallback;

        credentialStoreConnector.authenticate(callbacks);
        //No need for assertions. If the authentication fails, the test will fail
    }

    //TODO need to change expectedException to AuthenticationFailure
    @Test(priority = 2, expectedExceptions = {Throwable.class}, expectedExceptionsMessageRegExp =
            "Invalid username or password")
    public void testAuthenticationFailure() throws CredentialStoreException, IdentityStoreException,
            AuthenticationFailure {

        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        IdentityCallback<Map> carbonCallback = new IdentityCallback<>(null);

        Map<String, String> userData = new HashMap<>();
        userData.put(UserCoreConstants.USER_ID, "admin");
        carbonCallback.setContent(userData);

        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'm'});

        callbacks[0] = passwordCallback;
        callbacks[1] = carbonCallback;

        credentialStoreConnector.authenticate(callbacks);
    }

    //TODO need to change the expectedExceptions to CredentialStoreException
    @Test(priority = 3, expectedExceptions = {Exception.class}, expectedExceptionsMessageRegExp =
            "Unable to retrieve password information.*")
    public void testAuthenticationIncorrectUser() throws CredentialStoreException, IdentityStoreException,
            AuthenticationFailure {

        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        IdentityCallback<Map> carbonCallback = new IdentityCallback<>(null);

        Map<String, String> userData = new HashMap<>();
        userData.put(UserCoreConstants.USER_ID, "admin1");
        carbonCallback.setContent(userData);

        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});

        callbacks[0] = passwordCallback;
        callbacks[1] = carbonCallback;

        credentialStoreConnector.authenticate(callbacks);
    }

    @Test(priority = 4)
    public void testAddCredentialCallback() throws CredentialStoreException, IdentityStoreException,
            AuthenticationFailure {

        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        IdentityCallback<Map> carbonCallback = new IdentityCallback<>(null);

        Map<String, String> userData = new HashMap<>();
        userData.put(UserCoreConstants.USER_ID, "maduranga");
        carbonCallback.setContent(userData);

        passwordCallback.setPassword(new char[]{'m', 'a', 'd', 'u', 'r', 'a', 'n', 'g', 'a'});

        callbacks[0] = passwordCallback;
        callbacks[1] = carbonCallback;

        credentialStoreConnector.addCredential(callbacks);

        credentialStoreConnector.authenticate(callbacks);
        //No need for assertions. If the authentication fails, the test will fail
    }

    @Test(priority = 5)
    public void testUpdateCredentialCallback() throws CredentialStoreException, IdentityStoreException,
            AuthenticationFailure {

        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        IdentityCallback<Map> carbonCallback = new IdentityCallback<>(null);

        Map<String, String> userData = new HashMap<>();
        userData.put(UserCoreConstants.USER_ID, "maduranga");
        carbonCallback.setContent(userData);

        passwordCallback.setPassword(new char[]{'m', 'a', 'd', 'u', 'r', 'a', 'n', 'g', 'a', '1'});

        callbacks[0] = passwordCallback;
        callbacks[1] = carbonCallback;

        credentialStoreConnector.updateCredential(callbacks);
        credentialStoreConnector.authenticate(callbacks);
        //No need for assertions. If the authentication fails, the test will fail
    }

    @Test(priority = 6)
    public void testAddCredentialUsername() throws CredentialStoreException, IdentityStoreException,
            AuthenticationFailure {

        Callback[] callbacks = new Callback[1];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);

        passwordCallback.setPassword(new char[]{'t', 'h', 'a', 'n', 'u', 'j', 'a'});

        callbacks[0] = passwordCallback;

        credentialStoreConnector.addCredential("thanuja", callbacks);

        callbacks = new Callback[2];
        IdentityCallback<Map> carbonCallback = new IdentityCallback<>(null);

        Map<String, String> userData = new HashMap<>();
        userData.put(UserCoreConstants.USER_ID, "thanuja");
        carbonCallback.setContent(userData);

        callbacks[0] = passwordCallback;
        callbacks[1] = carbonCallback;

        credentialStoreConnector.authenticate(callbacks);
        //No need for assertions. If the authentication fails, the test will fail
    }

    @Test(priority = 7)
    public void testUpdateCredentialUsername() throws CredentialStoreException, IdentityStoreException,
            AuthenticationFailure {

        Callback[] callbacks = new Callback[1];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);

        passwordCallback.setPassword(new char[]{'t', 'h', 'a', 'n', 'u', 'j', 'a', '1'});

        callbacks[0] = passwordCallback;

        credentialStoreConnector.updateCredential("thanuja", callbacks);

        callbacks = new Callback[2];
        IdentityCallback<Map> carbonCallback = new IdentityCallback<>(null);

        Map<String, String> userData = new HashMap<>();
        userData.put(UserCoreConstants.USER_ID, "thanuja");
        carbonCallback.setContent(userData);

        callbacks[0] = passwordCallback;
        callbacks[1] = carbonCallback;

        credentialStoreConnector.authenticate(callbacks);
        //No need for assertions. If the authentication fails, the test will fail
    }

    @Test(priority = 8, expectedExceptions = {Exception.class}, expectedExceptionsMessageRegExp =
            "Unable to retrieve password information.*")
    public void testDeleteCredential() throws CredentialStoreException, AuthenticationFailure {

        credentialStoreConnector.deleteCredential("maduranga");

        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        IdentityCallback<Map> carbonCallback = new IdentityCallback<>(null);

        Map<String, String> userData = new HashMap<>();
        userData.put(UserCoreConstants.USER_ID, "maduranga");
        carbonCallback.setContent(userData);

        passwordCallback.setPassword(new char[]{'m', 'a', 'd', 'u', 'r', 'a', 'n', 'g', 'a'});

        callbacks[0] = passwordCallback;
        callbacks[1] = carbonCallback;

        credentialStoreConnector.authenticate(callbacks);
    }
}
