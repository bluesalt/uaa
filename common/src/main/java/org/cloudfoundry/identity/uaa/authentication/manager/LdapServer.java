package org.cloudfoundry.identity.uaa.authentication.manager;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

public class LdapServer {

    private String ldapServerURL;

    public LdapServer(String host, int port) {
        this.ldapServerURL = String.format("ldap://%s:%d", host, port);
    }

    public boolean authenticate(String username, String password) {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, this.ldapServerURL);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);

        try {
            new InitialDirContext(env);
        } catch (NamingException e) {
            return false;
        }

        return true;
    }
}
