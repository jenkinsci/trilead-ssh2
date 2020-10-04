package com.trilead.ssh2;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/*
    This is a test class for the Kerberos authentication, it requires an Kerberos environment
    it was tested with the environment defined here https://github.com/criteo/kerberos-docker.git

    "KRB5_HOST=krb5-service-instance-com"
    "KRB5_USER=bob"

    @author Kuisathaverat
 */
public class KerberosTest {

    @Before
    public void beforeMethod() {
        org.junit.Assume.assumeTrue(System.getenv("KRB5_HOST") != null);
        org.junit.Assume.assumeTrue(System.getenv("KRB5_USER") != null);
    }

    @Test
    public void testConnection() throws IOException {
        String host = System.getenv("KRB5_HOST");
        String user = System.getenv("KRB5_USER");
        Connection con = new Connection(host);
        con.connect();
        assertTrue(con.authenticateWithGssapiWithMic(user));
    }

    @Test
    public void testConnectionFAIL() throws IOException {
        String host = System.getenv("KRB5_HOST");
        String user = System.getenv("KRB5_USER");
        Connection con = new Connection(host);
        con.connect();
        assertFalse(con.authenticateWithGssapiWithMic(user + "NotExists"));
    }
}
