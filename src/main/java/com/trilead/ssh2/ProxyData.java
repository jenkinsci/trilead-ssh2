
package com.trilead.ssh2;

import java.io.IOException;
import java.net.Socket;

/**
 * An abstract marker interface implemented by all proxy data implementations.
 * 
 * @see HTTPProxyData
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: ProxyData.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */

public interface ProxyData
{
    Socket openConnection(Socket sock, String hostname, int port, int connectTimeout) throws IOException;
    //void close() throws IOException;
}
