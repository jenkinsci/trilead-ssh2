package com.trilead.ssh2.transport;


import org.assertj.core.util.xml.XmlStringPrettyFormatter;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;


import com.trilead.ssh2.log.Logger;

import static org.xmlunit.assertj3.XmlAssert.assertThat;



public class CallHomeTest {
     private static final Logger LOGGER = Logger.getLogger(CallHomeTest.class);
    private SshCallHomeClient sshCallHomeClient;
    private GenericContainer<?> netopeer2;
    
    @Before
    public void setup() {
        //setup logging from java.util.logger used in this project.
        JULLoggerSetup.setupJULLogger();
    }

    /**
     * This test creates a NETCONF server ( from Dockerfile) and 
     * configures it and triggers a SSH Call Home ( server acts as client and vice versa).
     * Then we start an SSH Client ( using this library). We wait for incoming
     * connection from server in accept(). Then when client and server are connected client send 
     * NETCONF {@code <hello>} message and read the same from NETCONF server.
     * For NETCONF server we use Netopeer2.
     * 
     * @see <a href="https://github.com/CESNET/netopeer2">https://github.com/CESNET/netopeer2/a>
     * 
     * @throws Exception if we fail 
     */
    @Test()
    public void triggerCallHome () throws Exception {

         // https://www.testcontainers.org/features/networking/
         Testcontainers.exposeHostPorts(4334);
       
        //Start server and trigger SSH Call Home.
        netopeer2 = new Netopeer2TestContainer().getNetopeer2Container();
        
        //Start client and wait for incoming calls from server
        sshCallHomeClient = new SshCallHomeClient();
        sshCallHomeClient.accept();
        //Send hello message from client.
        sshCallHomeClient.send(clientHelloMsg());
        //Wait to get a hello message from server.
        String message = sshCallHomeClient.read();
        LOGGER.log(50,"Message from node "+message);
        assertThat(XmlStringPrettyFormatter.xmlPrettyFormat(message)).and(XmlStringPrettyFormatter.xmlPrettyFormat(serverHelloMsg())).areSimilar();
     
        
    }

    @After
    public void cleanUp() {
        sshCallHomeClient.disconnect();
        netopeer2.stop();
        netopeer2.close();
    }


    private String clientHelloMsg(){
        return """
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
  </capabilities>
</hello>
]]>]]>
                """;
    }

    private String serverHelloMsg(){
        return """
                <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
	<capabilities>
		<capability>urn:ietf:params:netconf:base:1.0</capability>
		<capability>urn:ietf:params:netconf:base:1.1</capability>
		<capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>
		<capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
		<capability>urn:ietf:params:netconf:capability:confirmed-commit:1.1</capability>
		<capability>urn:ietf:params:netconf:capability:rollback-on-error:1.0</capability>
		<capability>urn:ietf:params:netconf:capability:validate:1.1</capability>
		<capability>urn:ietf:params:netconf:capability:startup:1.0</capability>
		<capability>urn:ietf:params:netconf:capability:xpath:1.0</capability>
		<capability>urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=explicit&amp;also-supported=report-all,report-all-tagged,trim,explicit</capability>
		<capability>urn:ietf:params:netconf:capability:notification:1.0</capability>
		<capability>urn:ietf:params:netconf:capability:interleave:1.0</capability>
		<capability>urn:ietf:params:netconf:capability:url:1.0?scheme=ftp,ftps,http,https,scp,sftp</capability>
		<capability>urn:ietf:params:xml:ns:yang:ietf-yang-metadata?module=ietf-yang-metadata&amp;revision=2016-08-05</capability>
		<capability>urn:ietf:params:xml:ns:yang:ietf-inet-types?module=ietf-inet-types&amp;revision=2013-07-15</capability>
		<capability>urn:ietf:params:xml:ns:yang:ietf-yang-types?module=ietf-yang-types&amp;revision=2013-07-15</capability>
		<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-acm?module=ietf-netconf-acm&amp;revision=2018-02-14</capability>
		<capability>urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&amp;content-id=2008448144</capability>
		<capability>urn:sysrepo:plugind?module=sysrepo-plugind&amp;revision=2022-08-26</capability>
		<capability>urn:ietf:params:xml:ns:netconf:base:1.0?module=ietf-netconf&amp;revision=2013-09-29&amp;features=writable-running,candidate,confirmed-commit,rollback-on-error,validate,startup,url,xpath</capability>
		<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults?module=ietf-netconf-with-defaults&amp;revision=2011-06-01</capability>
		<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications?module=ietf-netconf-notifications&amp;revision=2012-02-06</capability>
		<capability>urn:ietf:params:xml:ns:netconf:notification:1.0?module=notifications&amp;revision=2008-07-14</capability>
		<capability>urn:ietf:params:xml:ns:netmod:notification?module=nc-notifications&amp;revision=2008-07-14</capability>
		<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04</capability>
		<capability>urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name?module=ietf-x509-cert-to-name&amp;revision=2014-12-10</capability>
		<capability>urn:ietf:params:xml:ns:yang:iana-crypt-hash?module=iana-crypt-hash&amp;revision=2014-04-04&amp;features=crypt-hash-md5,crypt-hash-sha-256,crypt-hash-sha-512</capability>
	</capabilities>
    <session-id>1</session-id>
</hello>
                """;
    }

}
