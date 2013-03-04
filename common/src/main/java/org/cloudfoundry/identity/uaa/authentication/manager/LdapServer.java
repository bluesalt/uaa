package org.cloudfoundry.identity.uaa.authentication.manager;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;

public class LdapServer {

    private String ldapServerURL;
    private DirContext context;

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
            context = new InitialDirContext(env);
        } catch (NamingException e) {
            return false;
        }

        return true;
    }

    // TODO: This implementation is really kind of ugly. Use a more elegant solution. Maybe Spring's ldap framework ?
    public String getEmail(String username) {
        String mail = "";
        try {
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> results = context.search(username, "(mail=*)", constraints);
            if (results != null && results.hasMore()) {
                SearchResult sr = results.next();
                mail = sr.getAttributes().get("mail").get().toString();
            }
        } catch (NamingException e) {
            e.printStackTrace();
        }
        return mail;
    }
}
