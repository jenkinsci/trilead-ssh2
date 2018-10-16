package com.trilead.ssh2.transport;

import java.io.IOException;

/**
 * MessageHandler.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id : MessageHandler.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */
public interface MessageHandler
{
    /**
     * Handle message.
     *
     * @param msg    the msg
     * @param msglen the msglen
     * @throws IOException the io exception
     */
    public void handleMessage(byte[] msg, int msglen) throws IOException;

    /**
     * Called to inform that no more messages will be delivered.
     *
     * @param cause For diagnosis, the reason that caused the transport to close down.
     * @throws IOException the io exception
     */
    public void handleEndMessage(Throwable cause) throws IOException;
}
