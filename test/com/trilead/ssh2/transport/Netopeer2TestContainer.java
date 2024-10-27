package com.trilead.ssh2.transport;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;


import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import com.trilead.ssh2.log.Logger;


/**
 * This class uses testcontainers to create a generic testcontainer for 
 * Netopeer2 NETCONF server.
 */
 class Netopeer2TestContainer {

    private static final Logger LOGGER = Logger.getLogger(Netopeer2TestContainer.class);
    private static final String SSH_AUTH_CONFIG_FILE = "docker/ssh_listen.xml";
    private static final String SSH_CALL_HOME_CONFIG_FILE = "docker/ssh_callhome.xml";
    private static final String NACM_FILE = "docker/nacm.xml";
    private static final String DOCKER_IMAGE_NAME = "ghcr.io/jenkinsci/trilead-ssh2:netopeer-3.5.1";
    private static final int SSH_CALL_HOME_PORT = 4334;
    public static final String TESTCONTAINERS_HOST_NAME = "host.testcontainers.internal";
    private final Integer [] exposedPorts =  {830,4334};
    private GenericContainer<?> netopeer2;

    

   
    public Netopeer2TestContainer() throws Exception{
        initialize();
    }


    /**
     * Create dockerContainer
     * from Image with Netopeer2 and start 'netopeer2-server'. 
     * 
     * @throws Exception if we fail to create and start server.
     */
    private void initialize() throws Exception {
        
        netopeer2 = createContainer().withNetworkAliases(DOCKER_IMAGE_NAME);
        netopeer2.start();

        disableNacm(netopeer2);
        enableSshAuthMethod();
        enableSshCallHome();
        triggerSSHCallHome();
    }

    /**
     * Get the container with all the methods that can be performed
     * on the container using the testcontainer API {@code GenericContainer}
     * 
     * @return netopeer2 running as test container
     */
    public GenericContainer<?> getNetopeer2Container() {
        return netopeer2;
    }

    @SuppressWarnings("resource")
    private GenericContainer<?> createContainer() {
        assertTrue("Docker is not installed or docker client cannot be created!",DockerClientFactory.instance().isDockerAvailable());

        final JulLogConsumer julLogConsumer = new JulLogConsumer(LOGGER);
        return new GenericContainer<>(DockerImageName.parse(DOCKER_IMAGE_NAME)).withNetwork(null).withLogConsumer(julLogConsumer)
                .withExposedPorts(exposedPorts).withAccessToHost(true)
                .waitingFor(new LogMessageWaitStrategy().withRegEx(".*Listening on 0.0.0.0:830 for SSH connections.*"));
    }
  
    private void disableNacm(GenericContainer<?> netopeer2)
            throws InterruptedException, UnsupportedOperationException, IOException {
        MountableFile mountableFile = MountableFile
                .forClasspathResource(NACM_FILE);
        netopeer2.copyFileToContainer(mountableFile, "/opt/dev/nacm.xml");
        Container.ExecResult nacmFileCreatedRes = netopeer2.execInContainer("/bin/sh", "-c", "test -f /opt/dev/nacm.xml");
        LOGGER.log(50,"Message '"+nacmFileCreatedRes.getStdout()+"' and result '"+nacmFileCreatedRes.getExitCode()+"' of NACM file imported into docker.");
        Container.ExecResult nacmConfiguredRes = netopeer2.execInContainer("/bin/sh", "-c",
                "/usr/bin/sysrepocfg --import=/opt/dev/nacm.xml --datastore running --module ietf-netconf-acm");
        LOGGER.log(50,"Message '"+nacmConfiguredRes.getStdout()+"' and result '"+nacmConfiguredRes.getExitCode()+"' of NACM file executed in docker.");

    }

    private void enableSshAuthMethod() throws InterruptedException, UnsupportedOperationException, IOException {
        MountableFile mountableFile = MountableFile
                .forClasspathResource(SSH_AUTH_CONFIG_FILE);
        netopeer2.copyFileToContainer(mountableFile, "/opt/dev/ssh_listen.xml");
        Container.ExecResult sshAuthMethodFileCreatedRes = netopeer2.execInContainer("/bin/sh", "-c",
                "test -f /opt/dev/ssh_listen.xml");
        LOGGER.log(50,"Message '"+sshAuthMethodFileCreatedRes.getStdout()+"' and result '"+sshAuthMethodFileCreatedRes.getExitCode()+"' of SSH Auth method file imported into docker.");
        Container.ExecResult sshAuthMethodConfiguredRes = netopeer2.execInContainer("/bin/sh", "-c",
                "/usr/bin/sysrepocfg --import=/opt/dev/ssh_listen.xml --datastore running --module ietf-netconf-server");
        LOGGER.log(50,"Message '"+sshAuthMethodConfiguredRes.getStdout()+"' and result '"+sshAuthMethodConfiguredRes.getExitCode()+"'  of SSH Auth method file executed.");

    }

    private void   enableSshCallHome() throws InterruptedException, UnsupportedOperationException, IOException{
        MountableFile mountableFile = MountableFile
        .forClasspathResource(SSH_CALL_HOME_CONFIG_FILE);
    netopeer2.copyFileToContainer(mountableFile, "/opt/dev/ssh_callhome.xml");
    Container.ExecResult sshCallHomeFileCreatedRes = netopeer2.execInContainer("/bin/sh", "-c","test -f /opt/dev/ssh_callhome.xml");
    LOGGER.log(50,"Message '"+sshCallHomeFileCreatedRes.getStdout()+"' and result '"+sshCallHomeFileCreatedRes.getExitCode()+"' of SSH Call Home file imported into docker.");
    Container.ExecResult sshCallHomeConfiguredRes = netopeer2.execInContainer("/bin/sh", "-c",
        "/usr/bin/sysrepocfg --edit=/opt/dev/ssh_callhome.xml --datastore running --module ietf-netconf-server");
    LOGGER.log(50,"Message '"+sshCallHomeConfiguredRes.getStdout()+"' and result '"+sshCallHomeConfiguredRes.getExitCode()+"' of SSH Call Home file executed.");
    }

    private void triggerSSHCallHome() throws InterruptedException, UnsupportedOperationException, IOException{
         String content = triggerSSHCallHomeQuery(TESTCONTAINERS_HOST_NAME,SSH_CALL_HOME_PORT);
        File tempFile = createTempFileWithContent(content);
         netopeer2.copyFileToContainer(MountableFile.forHostPath(tempFile.getAbsolutePath()), "/opt/dev/enable_callhome.xml");
        Container.ExecResult sshEnableCallHomeFileCreatedRes = netopeer2.execInContainer("/bin/sh", "-c","test -f /opt/dev/enable_callhome.xml");
        LOGGER.log(50,"Message '"+sshEnableCallHomeFileCreatedRes.getStdout()+"' and result '"+sshEnableCallHomeFileCreatedRes.getExitCode()+"' of Enable SSH Call Home Query file imported into docker.");
        Container.ExecResult sshEnableCallHomeConfiguredRes = netopeer2.execInContainer("/bin/sh", "-c", "/usr/bin/sysrepocfg --edit=/opt/dev/enable_callhome.xml --datastore running");
        LOGGER.log(50,"Message '"+sshEnableCallHomeConfiguredRes.getStdout()+"' and result '"+sshEnableCallHomeConfiguredRes.getExitCode()+"'  of Enable SSH Call Home Query file sent.");
    
    }

    private static File createTempFileWithContent(String content) throws IOException {
        File tempFile = File.createTempFile("testfile", ".txt");

        try (FileWriter writer = new FileWriter(tempFile)) {
            writer.write(content);
        }

        return tempFile;
    }
 
    private String triggerSSHCallHomeQuery(String ip, int port) {
        String message = """
                              <netconf-server xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-server">
                    <call-home>
                        <netconf-client>
                            <name>default-client</name>
                            <endpoints>
                                <endpoint>
                                    <name>default-ssh</name>
                                    <ssh>
                                        <tcp-client-parameters>
                                            <remote-address>%s</remote-address>
                                            <remote-port>%d</remote-port>
                                        </tcp-client-parameters>
                                        <ssh-server-parameters>
                                            <server-identity>
                                                <host-key>
                                                    <name>default-key</name>
                                                    <public-key>
                                                        <central-keystore-reference>genkey</central-keystore-reference>
                                                    </public-key>
                                                </host-key>
                                            </server-identity>
                                            <client-authentication>
                                                <endpoint-reference xmlns="urn:cesnet:libnetconf2-netconf-server">default-ssh</endpoint-reference>
                                            </client-authentication>
                                        </ssh-server-parameters>
                                    </ssh>
                                </endpoint>
                            </endpoints>
                            <connection-type>
                                <persistent/>
                            </connection-type>
                        </netconf-client>
                    </call-home>
                </netconf-server>
                                """;
        return message.formatted(ip, port);

    }


}
