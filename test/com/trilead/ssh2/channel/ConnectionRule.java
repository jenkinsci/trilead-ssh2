package com.trilead.ssh2.channel;

import com.trilead.ssh2.Connection;
import org.junit.Rule;
import org.junit.rules.ExternalResource;

import java.io.File;

/**
 * Connect to a remote SSH server
 *
 * @author Kohsuke Kawaguchi
 */
public class ConnectionRule extends ExternalResource {
    private Connection connection;

    public Connection getConnection() throws Exception {
        if (connection==null)   // in case this is used outside JUnit
            before();
        return connection;
    }

    @Override
    public void before() throws Exception {
        connection = new Connection("127.0.0.2");
        connection.setTCPNoDelay(true);
        connection.connect();

        connection.authenticateWithPublicKey("kohsuke",new File("/home/kohsuke/.ssh/id_rsa"),null);
    }

    @Override
    public void after() {
        if (connection!=null)
            connection.close();
    }
}
