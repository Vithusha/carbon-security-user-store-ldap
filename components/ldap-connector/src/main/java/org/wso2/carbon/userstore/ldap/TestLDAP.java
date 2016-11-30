package org.wso2.carbon.userstore.ldap;


import org.wso2.carbon.identity.mgt.bean.Attribute;
import org.wso2.carbon.identity.mgt.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreConnectorException;
import org.wso2.carbon.userstore.ldap.connector.LDAPIdentityStoreConnector;
import org.wso2.carbon.userstore.ldap.datasource.LDAPConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by wso2 on 11/28/16.
 */
public class TestLDAP {


//    private static IdentityStoreConnector identityStoreConnector;
//    protected static IdentityStoreConnectorFactory identityStoreConnectorFactory;
    public static void  main(String[] args) throws IdentityStoreConnectorException {

//        IdentityStoreConnectorConfig identityStoreConnectorConfig = new IdentityStoreConnectorConfig();
//        identityStoreConnector=identityStoreConnectorFactory.getInstance();
//        identityStoreConnectorConfig.setConnectorId("LDAPIS1");
//        identityStoreConnectorConfig.setConnectorType("LDAPPrivilegedIdentityStore");
//
        IdentityStoreConnectorConfig identityStoreConnectorConfig = new IdentityStoreConnectorConfig();
        Map<String, String> properties =new HashMap<>();
        properties.put(LDAPConstants.LDAP_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        properties.put(LDAPConstants.CONNECTION_URL, "ldap://localhost:389/dc=wso2,dc=com");
        properties.put(LDAPConstants.CONNECTION_NAME, "cn=admin,dc=wso2,dc=com");
        properties.put(LDAPConstants.CONNECTION_PASSWORD, "admin");
        properties.put(LDAPConstants.AUTHENTICATION_TYPE,"simple");
        properties.put("connectorUserId", "uid");
        properties.put("connectorGroupId", "groupname");
        identityStoreConnectorConfig.setProperties(properties);
//        identityStoreConnector.init(identityStoreConnectorConfig);
//        identityStoreConnector.getIdentityStoreConnectorId();


        LDAPIdentityStoreConnector ldapidentityStoreConnector = new LDAPIdentityStoreConnector();
        ldapidentityStoreConnector.init(identityStoreConnectorConfig);


        List<Attribute> attributes = new ArrayList<>();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("uid");
        attribute1.setAttributeValue("maduranga");
        attributes.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("telephoneNumber");
        attribute2.setAttributeValue("94773456789");
        attributes.add(attribute2);
        Attribute attribute3 = new Attribute();
        attribute3.setAttributeName("givenName");
        attribute3.setAttributeValue("Maduranga");
        attributes.add(attribute3);
        Attribute attribute4 = new Attribute();
        attribute4.setAttributeName("sn");
        attribute4.setAttributeValue("Siriwardena");
        attributes.add(attribute4);

        ldapidentityStoreConnector.getUserAttributeValues("Maduranga");


    }
}
