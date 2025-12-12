package com.trilead.ssh2.channel;

import com.trilead.ssh2.Connection;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.rules.ExternalResource;
import org.testcontainers.containers.GenericContainer;

import static org.junit.Assert.assertTrue;

/**
 * Connect to a remote SSH server
 *
 * @author Kohsuke Kawaguchi
 */
public class ConnectionRule extends ExternalResource {
    public static final String USER = "jenkins";
    public static final int SSH_PORT = 22;

    @Rule
    public GenericContainer<?> sshContainer = new GenericContainer<>("jenkins/ssh-agent");

    private Connection connection;

    public Connection getConnection() throws Exception {
        if (connection==null)   // in case this is used outside JUnit
            before();
        return connection;
    }

    @Override
    public void before() throws Exception {
        String publicKey = IOUtils.toString(getClass().getResourceAsStream("../crypto/cipher/key.pem.pub"));
        String privateKey =  IOUtils.toString(getClass().getResourceAsStream("../crypto/cipher/key.pem"));
        sshContainer.withEnv("JENKINS_AGENT_SSH_PUBKEY", publicKey)
                    .withExposedPorts(SSH_PORT)
                    .start();

        int port = sshContainer.getMappedPort(SSH_PORT);
        String ip = sshContainer.getContainerIpAddress();

        connection = new Connection(ip, port);
        connection.enableDebugging(true, null);
        connection.setTCPNoDelay(true);
        connection.connect();

        connection.authenticateWithPublicKey(USER, privateKey.toCharArray(),null);
        assertTrue(connection.isAuthenticationComplete());
    }

    @Override
    public void after() {
        if (connection!=null)
            connection.close();
    }
}
