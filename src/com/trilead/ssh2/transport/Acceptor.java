package com.trilead.ssh2.transport;

import java.io.IOException;
import java.net.SocketTimeoutException;

import com.trilead.ssh2.Connection;
import com.trilead.ssh2.ConnectionInfo;
import com.trilead.ssh2.ServerHostKeyVerifier;

/**
 * This class is similar to {@link Connection} but is
 * used to accept incoming connections from clients.
 * Example use-cases are 'NETCONF Call Home' or
 * 'reverse SSH'.
 * 
 */
public class Acceptor extends Connection{

    /**
     * Constuctor
     * @param hostname is the hostname that this class is running on.
     * @param port is the port that is used for incoming connections.
     */
    public Acceptor(String hostname,int port){
        super(hostname,port);
    }
    /**
     * This method reuses most of methods for {@link Connection#connect(ServerHostKeyVerifier, int, int, int)}. Parameters and descriptions applies here too.
     * The main difference between 
     * this class and {@Connection} is that we use {@ServerSocket} and we bind with the port specified in constructor. The {@link ServerSocket#accept()}
     * will wait (blocks) for an incoming connection for max {@param connectTimeout} . If connection is completed a {@Socket} is returned and we set a timeout of this socket using 
     * {@param readTimeout}.
     * 
     * @throws SocketTimeoutException If there is no incoming connection within  {@param connectTimeout}.
     *  
     */
    public ConnectionInfo accept(ServerHostKeyVerifier verifier, int connectTimeout, int readTimeout, int kexTimeout) throws IOException{
        if (tm != null) {
            throw new IOException("Connection to " + hostname + " is already in connected state!");
        }
        if (connectTimeout < 0)
            throw new IllegalArgumentException("connectTimeout must be non-negative!");

        if (kexTimeout < 0)
            throw new IllegalArgumentException("kexTimeout must be non-negative!");

        tm = new TransportManager(hostname, port);
        tm.setEnabledCallHomeSSH(true);

        tm.setConnectionMonitors(connectionMonitors);
        try {
            tm.initialize(cryptoWishList, verifier, dhgexpara, connectTimeout, readTimeout, getOrCreateSecureRND(),
                    proxyData);
        } catch (SocketTimeoutException ste) {
            throw (SocketTimeoutException) new SocketTimeoutException(
                    "The accept() operation on the socket timed out.").initCause(ste);
        }

        tm.setTcpNoDelay(tcpNoDelay);

        /* Wait until first KEX has finished */
        return tm.getConnectionInfo(1);
    }

}
