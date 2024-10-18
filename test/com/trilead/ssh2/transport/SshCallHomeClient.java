package com.trilead.ssh2.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;

import java.util.concurrent.TimeUnit;

import com.trilead.ssh2.ServerHostKeyVerifier;
import com.trilead.ssh2.Session;

import com.trilead.ssh2.log.Logger;

/**
 * This is a very simple client wrapping this library.
 * It supports accepting incoming connections 
 * from a NETCONF server. Once accept is complete we can
 * send a simple NETCONF {@code <hello>} message and expect 
 * to receive the same from server. 
 * 
 * This client is only used to test a limited send/read sequence.
 * Nor is it a complete NETCONF client.
 */
class SshCallHomeClient {
    private static final Logger LOGGER = Logger.getLogger(SshCallHomeClient.class);
    private static final String HOSTNAME = "host.testcontainers.internal";
    private static final int SSH_CALL_HOME_PORT = 4334;
    private static final String USER = "netconf";
    private static final String PASSWORD = "netconf";
    private static final int BUFFER_SIZE = 9 * 1024;
    private static final String NETCONF_PROMPT = "]]>]]>";
    private static final int  DEFAULT_SEND_TIME_OUT = 5000;
    private static final String SUBSYSTEM = "netconf";

    private Acceptor acceptor;
    private Session session;
    


     void accept() throws IOException {  
            acceptor = new Acceptor(HOSTNAME,SSH_CALL_HOME_PORT);
               // Implementing a fake HostKeyVerifier that always returns true
            ServerHostKeyVerifier serverHostKeyVerifier = new MyServerHostKeyVerifierImpl();
            acceptor.accept(serverHostKeyVerifier,400000,400000,40000);
            auth();
            session = acceptor.openSession();
            session.startSubSystem(SUBSYSTEM);
       
     }

     void send(String msg) {
        OutputStream stdin = session.getStdin();
        try {
            stdin.write(msg.getBytes());
            LOGGER.log(50,"--> Sent message"+msg);
            stdin.flush();
        } catch (IOException e) {
            LOGGER.log(50,"Could not send message");
            
          
        }
       

     }

     String read()throws IOException{
        InputStream stdout = session.getStdout();
        final char[] buffer = new char[BUFFER_SIZE];
            final StringBuilder rpcReply = new StringBuilder();
            final long startTime = System.nanoTime();
            final Reader in = new InputStreamReader(stdout, Charset.forName("UTF-8"));
            boolean timeoutNotExceeded = true;
            int promptPosition;
            while ((promptPosition = rpcReply.indexOf(NETCONF_PROMPT)) < 0 &&
                    (timeoutNotExceeded = (TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime) < DEFAULT_SEND_TIME_OUT))) {
                int charsRead = in.read(buffer, 0, buffer.length);
                if (charsRead < 0) throw new IOException("Input Stream has been closed during reading.");
                rpcReply.append(buffer, 0, charsRead);
            }
    
            if (!timeoutNotExceeded){
                throw new SocketTimeoutException("Command send timeout limit was exceeded: " + DEFAULT_SEND_TIME_OUT );
            }
            // fixing the rpc reply by removing device prompt
            LOGGER.log(50,"<-- Received message:\n "+rpcReply);
            rpcReply.setLength(promptPosition);
            return rpcReply.toString();
        
     }

    void disconnect(){
        acceptor.close();
     }

    private void auth() throws IOException {
        boolean isAuthenticated = acceptor.authenticateWithPassword(USER,
                PASSWORD);
        if (!isAuthenticated) {
            throw new IOException("Authentication failed.");
        }

    }




}
