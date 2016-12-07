package org.wso2.carbon.userstore.ldap;


import org.wso2.carbon.identity.mgt.bean.Attribute;
import org.wso2.carbon.identity.mgt.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreConnectorException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreConnectorException;
import org.wso2.carbon.userstore.ldap.connector.LDAPIdentityStoreConnector;
import org.wso2.carbon.userstore.ldap.datasource.utils.LDAPConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by wso2 on 11/28/16.
 */
public class TestLDAP {


    public static void  main(String[] args) throws IdentityStoreConnectorException {


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
        identityStoreConnectorConfig.setConnectorId("LDAPIdentityStore");


        LDAPIdentityStoreConnector ldapidentityStoreConnector = new LDAPIdentityStoreConnector();
        ldapidentityStoreConnector.init(identityStoreConnectorConfig);


        List<Attribute> attributes = new ArrayList<>();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("uid");
        attribute1.setAttributeValue("Damith");
        attributes.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("telephoneNumber");
        attribute2.setAttributeValue("94770000000");
        attributes.add(attribute2);
        Attribute attribute3 = new Attribute();
        attribute3.setAttributeName("givenName");
        attribute3.setAttributeValue("Perera");
        attributes.add(attribute3);
        Attribute attribute4 = new Attribute();
        attribute4.setAttributeName("sn");
        attribute4.setAttributeValue("Perera");
        attributes.add(attribute4);

        String newID = ldapidentityStoreConnector.addUser(attributes);
        System.out.println("userID is : " +newID);

        List<Attribute> attributeList = ldapidentityStoreConnector.getUserAttributeValues("Dyan");
        printAttributes(attributeList);

        ldapidentityStoreConnector.deleteUser("Damith");



    }

    public static void printAttributes(List<Attribute> attributes){

        for(Attribute attr : attributes)
        {
            System.out.println("Attribute Name: " + attr.getAttributeName().toString() + "     Value: " + attr.getAttributeValue().toString());
        }
    }

//    CredentialStoreConnectorConfiguration
    public CredentialStoreConnectorConfig setCredentialStoreConnectorConfig() throws CredentialStoreConnectorException {


        CredentialStoreConnectorConfig credentialStoreConnectorConfig = new CredentialStoreConnectorConfig();
        Map<String, String> properties = new HashMap<>();


        properties.put(LDAPConstants.LDAP_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        properties.put(LDAPConstants.CONNECTION_URL, "ldap://localhost:389/dc=wso2,dc=com");
        properties.put(LDAPConstants.CONNECTION_NAME, "cn=admin,dc=wso2,dc=com");
        properties.put(LDAPConstants.CONNECTION_PASSWORD, "admin");
        properties.put(LDAPConstants.AUTHENTICATION_TYPE, "simple");
        properties.put("connectorUserId", "uid");
        properties.put("connectorGroupId", "groupname");


        credentialStoreConnectorConfig.setProperties(properties);
        credentialStoreConnectorConfig.setConnectorId("LDAPCredentialStore");

    return  credentialStoreConnectorConfig;

    }

}
