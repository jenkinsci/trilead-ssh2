
package com.trilead.ssh2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;

import com.trilead.ssh2.channel.Channel;
import com.trilead.ssh2.channel.ChannelManager;
import com.trilead.ssh2.channel.X11ServerData;
import com.trilead.ssh2.packets.PacketSignal;


/**
 * A Session is a remote execution of a program. "Program" means
 * in this context either a shell, an application or a system command. The
 * program may or may not have a tty. Only one single program can be started on
 * a session. However, multiple sessions can be active simultaneously.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: Session.java,v 1.2 2008/03/03 07:01:36 cplattne Exp $
 */
public class Session
{
	ChannelManager cm;
	Channel cn;

	boolean flag_pty_requested = false;
	boolean flag_x11_requested = false;
	boolean flag_execution_started = false;
	boolean flag_closed = false;

	String x11FakeCookie = null;

	final SecureRandom rnd;
	
	Session(ChannelManager cm, SecureRandom rnd) throws IOException
	{
		this.cm = cm;
		this.cn = cm.openSessionChannel();
		this.rnd = rnd;
	}

	/**
	 * Basically just a wrapper for lazy people - identical to calling
	 * requestPTY("dumb", 0, 0, 0, 0, null).
	 * 
	 * @throws IOException the io exception
	 */
	public void requestDumbPTY() throws IOException
	{
		requestPTY("dumb", 0, 0, 0, 0, null);
	}

	/**
	 * Basically just another wrapper for lazy people - identical to calling
	 * requestPTY(term, 0, 0, 0, 0, null).
	 *
	 * @param term the term
	 * @throws IOException the io exception
	 */
	public void requestPTY(String term) throws IOException
	{
		requestPTY(term, 0, 0, 0, 0, null);
	}

	/**
	 * Allocate a pseudo-terminal for this session.
	 * <p>
	 * This method may only be called before a program or shell is started in
	 * this session.
	 * <p>
	 * Different aspects can be specified:
	 *
	 * <ul>
	 * <li>The TERM environment variable value (e.g., vt100)</li>
	 * <li>The terminal's dimensions.</li>
	 * <li>The encoded terminal modes.</li>
	 * </ul>
	 * Zero dimension parameters are ignored. The character/row dimensions
	 * override the pixel dimensions (when nonzero). Pixel dimensions refer to
	 * the drawable area of the window. The dimension parameters are only
	 * informational. The encoding of terminal modes (parameter
	 * terminal_modes) is described in RFC4254.
	 * 
	 * @param term
	 *            The TERM environment variable value (e.g., vt100)
	 * @param term_width_characters
	 *            terminal width, characters (e.g., 80)
	 * @param term_height_characters
	 *            terminal height, rows (e.g., 24)
	 * @param term_width_pixels
	 *            terminal width, pixels (e.g., 640)
	 * @param term_height_pixels
	 *            terminal height, pixels (e.g., 480)
	 * @param terminal_modes
	 *            encoded terminal modes (may be null)
	 * @throws IOException the io exception
	 */
	public void requestPTY(String term, int term_width_characters, int term_height_characters, int term_width_pixels,
			int term_height_pixels, byte[] terminal_modes) throws IOException
	{
		if (term == null)
			throw new IllegalArgumentException("TERM cannot be null.");

		if ((terminal_modes != null) && (terminal_modes.length > 0))
		{
			if (terminal_modes[terminal_modes.length - 1] != 0)
				throw new IOException("Illegal terminal modes description, does not end in zero byte");
		}
		else
			terminal_modes = new byte[] { 0 };

		synchronized (this)
		{
			/* The following is just a nicer error, we would catch it anyway later in the channel code */
			if (flag_closed)
				throw new IOException("This session is closed.");

			if (flag_pty_requested)
				throw new IOException("A PTY was already requested.");

			if (flag_execution_started)
				throw new IOException(
						"Cannot request PTY at this stage anymore, a remote execution has already started.");

			flag_pty_requested = true;
		}

		cm.requestPTY(cn, term, term_width_characters, term_height_characters, term_width_pixels, term_height_pixels,
				terminal_modes);
	}

    /**
     * Tells the server that the size of the terminal has changed.
     *
     * See {@link #requestPTY(String, int, int, int, int, byte[])} for more details about how parameters are interpreted.
   	 *
   	 * @param term_width_characters
   	 *            terminal width, characters (e.g., 80)
   	 * @param term_height_characters
   	 *            terminal height, rows (e.g., 24)
   	 * @param term_width_pixels
   	 *            terminal width, pixels (e.g., 640)
   	 * @param term_height_pixels
   	 *            terminal height, pixels (e.g., 480)
   	 * @throws IOException the io exception
   	 */
   	public void requestWindowChange(int term_width_characters, int term_height_characters, int term_width_pixels,
   			int term_height_pixels) throws IOException
   	{
   		synchronized (this)
   		{
   			/* The following is just a nicer error, we would catch it anyway later in the channel code */
   			if (flag_closed)
   				throw new IOException("This session is closed.");

   			if (!flag_pty_requested)
   				throw new IOException("A PTY was not requested.");
   		}

   		cn.requestWindowChange(term_width_characters, term_height_characters, term_width_pixels, term_height_pixels);
   	}

	/**
	 * Sends a signal to the remote process.
	 *
	 * @param name the name
	 * @throws IOException the io exception
	 */
	public void signal(String name) throws IOException {
        synchronized (this) {
            /* The following is just a nicer error, we would catch it anyway later in the channel code */
            if (flag_closed)
                throw new IOException("This session is closed.");
        }

        cn.signal(name);
    }

	/**
	 * Sends a signal to the remote process.
	 * <p>
	 * For better portability, specify signal by name, not by its number.
	 *
	 * @param code the code
	 * @throws IOException the io exception
	 */
	public void signal(int code) throws IOException {
        String sig = PacketSignal.strsignal(code);
        if (sig==null)  throw new IllegalArgumentException("Unrecognized signal code: "+code);
        signal(sig);
    }

    /**
	 * Request X11 forwarding for the current session.
	 * <p>
	 * You have to supply the name and port of your X-server.
	 * <p>
	 * This method may only be called before a program or shell is started in
	 * this session.
	 * 
	 * @param hostname the hostname of the real (target) X11 server (e.g., 127.0.0.1)
	 * @param port the port of the real (target) X11 server (e.g., 6010)
	 * @param cookie if non-null, then present this cookie to the real X11 server
	 * @param singleConnection if true, then the server is instructed to only forward one single
	 *        connection, no more connections shall be forwarded after first, or after the session
	 *        channel has been closed
	 * @throws IOException the io exception
	 */
	public void requestX11Forwarding(String hostname, int port, byte[] cookie, boolean singleConnection)
			throws IOException
	{
		if (hostname == null)
			throw new IllegalArgumentException("hostname argument may not be null");

		synchronized (this)
		{
			/* The following is just a nicer error, we would catch it anyway later in the channel code */
			if (flag_closed)
				throw new IOException("This session is closed.");

			if (flag_x11_requested)
				throw new IOException("X11 forwarding was already requested.");

			if (flag_execution_started)
				throw new IOException(
						"Cannot request X11 forwarding at this stage anymore, a remote execution has already started.");

			flag_x11_requested = true;
		}

		/* X11ServerData - used to store data about the target X11 server */

		X11ServerData x11data = new X11ServerData();

		x11data.hostname = hostname;
		x11data.port = port;
		x11data.x11_magic_cookie = cookie; /* if non-null, then present this cookie to the real X11 server */

		/* Generate fake cookie - this one is used between remote clients and our proxy */

		byte[] fakeCookie = new byte[16];
		String hexEncodedFakeCookie;

		/* Make sure that this fake cookie is unique for this connection */

		while (true)
		{
			rnd.nextBytes(fakeCookie);

			/* Generate also hex representation of fake cookie */

			StringBuffer tmp = new StringBuffer(32);
			for (int i = 0; i < fakeCookie.length; i++)
			{
				String digit2 = Integer.toHexString(fakeCookie[i] & 0xff);
				tmp.append((digit2.length() == 2) ? digit2 : "0" + digit2);
			}
			hexEncodedFakeCookie = tmp.toString();

			/* Well, yes, chances are low, but we want to be on the safe side */

			if (cm.checkX11Cookie(hexEncodedFakeCookie) == null)
				break;
		}

		/* Ask for X11 forwarding */

		cm.requestX11(cn, singleConnection, "MIT-MAGIC-COOKIE-1", hexEncodedFakeCookie, 0);

		/* OK, that went fine, get ready to accept X11 connections... */
		/* ... but only if the user has not called close() in the meantime =) */

		synchronized (this)
		{
			if (flag_closed == false)
			{
				this.x11FakeCookie = hexEncodedFakeCookie;
				cm.registerX11Cookie(hexEncodedFakeCookie, x11data);
			}
		}

		/* Now it is safe to start remote X11 programs */
	}

	/**
	 * Execute a command on the remote machine.
	 * 
	 * @param cmd
	 *            The command to execute on the remote host.
	 * @throws IOException the io exception
	 */
	public void execCommand(String cmd) throws IOException
	{
		if (cmd == null)
			throw new IllegalArgumentException("cmd argument may not be null");

		synchronized (this)
		{
			/* The following is just a nicer error, we would catch it anyway later in the channel code */
			if (flag_closed)
				throw new IOException("This session is closed.");

			if (flag_execution_started)
				throw new IOException("A remote execution has already started.");

			flag_execution_started = true;
		}

		cm.requestExecCommand(cn, cmd);
	}

	/**
	 * Start a shell on the remote machine.
	 * 
	 * @throws IOException the io exception
	 */
	public void startShell() throws IOException
	{
		synchronized (this)
		{
			/* The following is just a nicer error, we would catch it anyway later in the channel code */
			if (flag_closed)
				throw new IOException("This session is closed.");

			if (flag_execution_started)
				throw new IOException("A remote execution has already started.");

			flag_execution_started = true;
		}

		cm.requestShell(cn);
	}

	/**
	 * Start a subsystem on the remote machine.
	 * Unless you know what you are doing, you will never need this.
	 * 
	 * @param name the name of the subsystem.
	 * @throws IOException the io exception
	 */
	public void startSubSystem(String name) throws IOException
	{
		if (name == null)
			throw new IllegalArgumentException("name argument may not be null");

		synchronized (this)
		{
			/* The following is just a nicer error, we would catch it anyway later in the channel code */
			if (flag_closed)
				throw new IOException("This session is closed.");

			if (flag_execution_started)
				throw new IOException("A remote execution has already started.");

			flag_execution_started = true;
		}

		cm.requestSubSystem(cn, name);
	}

	/**
	 * This method can be used to perform end-to-end session (i.e., SSH channel)
	 * testing. It sends a 'ping' message to the server and waits for the 'pong'
	 * from the server.
	 * <p>
	 * Implementation details: this method sends a SSH_MSG_CHANNEL_REQUEST request
	 * ('trilead-ping') to the server and waits for the SSH_MSG_CHANNEL_FAILURE reply
	 * packet.
	 * 
	 * @throws IOException in case of any problem or when the session is closed
	 */
	public void ping() throws IOException
	{
		synchronized (this)
		{
			/*
			 * The following is just a nicer error, we would catch it anyway
			 * later in the channel code
			 */
			if (flag_closed)
				throw new IOException("This session is closed.");
		}

		cm.requestChannelTrileadPing(cn);
	}
	
	public InputStream getStdout()
	{
		return cn.getStdoutStream();
	}

	public InputStream getStderr()
	{
		return cn.getStderrStream();
	}

	public OutputStream getStdin()
	{
		return cn.getStdinStream();
	}

	/**
	 * Write stdout received from the other side to the specified {@link OutputStream}.
	 *
	 * <p>
	 * By default, when data arrives from the other side, trilead buffers them and lets
	 * you read it at your convenience from {@link #getStdout()}. This is normally convenient,
	 * but if all you are doing is to send the data to another {@link OutputStream} by
	 * copying a stream, then you'll be end up wasting a thread just for this.
	 * In such a situation, you can call this method and let the I/O handling thread of trilead
	 * directly pass the received data to the output stream. This also eliminates the internal
	 * buffer used for spooling.
	 *
	 * <p>
	 * When you do this, beware of a blocking write! If a write blocks, it'll affect
	 * all the other channels and sessions that are sharing the same SSH connection,
	 * as there's only one I/O thread. For example, this can happen if you are writing to
	 * {@link Socket}.
	 *
	 * <p>
	 * If any data has already been received and spooled before calling this method,
	 * the data will be sent to the given stream immediately.
	 *
	 * <p>
	 * To signal the end of the stream, when the other side notifies us of EOF or when
	 * the channel closes, the output stream gets closed. If this is not desirable,
	 * you must wrap the output stream and ignore the {@link OutputStream#close()} call.
	 *
	 * @param os the os
	 * @throws IOException the io exception
	 */
	public void pipeStdout(OutputStream os) throws IOException {
        cn.pipeStdoutStream(os);
    }

	/**
	 * The same as {@link #pipeStdout(OutputStream)} except for stderr, not for stdout.
	 *
	 * @param os the os
	 * @throws IOException the io exception
	 */
	public void pipeStderr(OutputStream os) throws IOException {
        cn.pipeStderrStream(os);
    }

	/**
	 * This method blocks until there is more data available on either the
	 * stdout or stderr InputStream of this Session. Very useful
	 * if you do not want to use two parallel threads for reading from the two
	 * InputStreams. One can also specify a timeout. NOTE: do NOT call this
	 * method if you use concurrent threads that operate on either of the two
	 * InputStreams of this Session (otherwise this method may
	 * block, even though more data is available).
	 * 
	 * @param timeout
	 *            The (non-negative) timeout in ms. 0 means no
	 *            timeout, the call may block forever.
	 * @return
	 *            <ul>
	 *            <li>0 if no more data will arrive.</li>
	 *            <li>1 if more data is available.</li>
	 *            <li>-1 if a timeout occurred.</li>
	 *            </ul>
	 *            
	 * @throws    IOException the io exception
	 * @throws    InterruptedException the interrupted exception
	 * @deprecated This method has been replaced with a much more powerful wait-for-condition
	 *             interface and therefore acts only as a wrapper.
	 * 
	 */
	public int waitUntilDataAvailable(long timeout) throws IOException, InterruptedException {
		if (timeout < 0)
			throw new IllegalArgumentException("timeout must not be negative!");

		int conditions = cm.waitForCondition(cn, timeout, ChannelCondition.STDOUT_DATA | ChannelCondition.STDERR_DATA
				| ChannelCondition.EOF);

		if ((conditions & ChannelCondition.TIMEOUT) != 0)
			return -1;

		if ((conditions & (ChannelCondition.STDOUT_DATA | ChannelCondition.STDERR_DATA)) != 0)
			return 1;

		/* Here we do not need to check separately for CLOSED, since CLOSED implies EOF */

		if ((conditions & ChannelCondition.EOF) != 0)
			return 0;

		throw new IllegalStateException("Unexpected condition result (" + conditions + ")");
	}

	/**
	 * This method blocks until certain conditions hold true on the underlying SSH-2 channel.
	 * <p>
	 * This method returns as soon as one of the following happens:
	 * <ul>
	 * <li>at least of the specified conditions (see {@link ChannelCondition}) holds true</li>
	 * <li>timeout &gt; 0 and a timeout occured (TIMEOUT will be set in result conditions)</li>
	 * <li>the underlying channel was closed (CLOSED will be set in result conditions)</li>
	 * </ul>
	 * <p>
	 * In any case, the result value contains ALL current conditions, which may be more
	 * than the specified condition set (i.e., never use the "==" operator to test for conditions
	 * in the bitmask, see also comments in {@link ChannelCondition}).
	 * <p>
	 * Note: do NOT call this method if you want to wait for STDOUT_DATA or STDERR_DATA and
	 * there are concurrent threads (e.g., StreamGobblers) that operate on either of the two
	 * InputStreams of this Session (otherwise this method may
	 * block, even though more data is available in the StreamGobblers).
	 *
	 * @param condition_set a bitmask based on {@link ChannelCondition} values
	 * @param timeout       non-negative timeout in ms, 0 means no timeout
	 * @return all bitmask specifying all current conditions that are true
	 * @throws InterruptedException the interrupted exception
	 */
	public int waitForCondition(int condition_set, long timeout) throws InterruptedException {
		if (timeout < 0)
			throw new IllegalArgumentException("timeout must be non-negative!");

		return cm.waitForCondition(cn, timeout, condition_set);
	}

	/**
	 * Get the exit code/status from the remote command - if available. Be
	 * careful - not all server implementations return this value. It is
	 * generally a good idea to call this method only when all data from the
	 * remote side has been consumed (see also the WaitForCondition method).
	 * 
	 * @return An Integer holding the exit code, or
	 *         null if no exit code is (yet) available.
	 */
	public Integer getExitStatus()
	{
		return cn.getExitStatus();
	}

	/**
	 * Get the name of the signal by which the process on the remote side was
	 * stopped - if available and applicable. Be careful - not all server
	 * implementations return this value.
	 * 
	 * @return An String holding the name of the signal, or
	 *         null if the process exited normally or is still
	 *         running (or if the server forgot to send this information).
	 */
	public String getExitSignal()
	{
		return cn.getExitSignal();
	}

	/**
	 * Close this session. NEVER forget to call this method to free up resources -
	 * even if you got an exception from one of the other methods (or when
	 * getting an Exception on the Input- or OutputStreams). Sometimes these other
	 * methods may throw an exception, saying that the underlying channel is
	 * closed (this can happen, e.g., if the other server sent a close message.)
	 * However, as long as you have not called the close()
	 * method, you may be wasting (local) resources.
	 * 
	 */
	public void close()
	{
		synchronized (this)
		{
			if (flag_closed)
				return;

			flag_closed = true;

			if (x11FakeCookie != null)
				cm.unRegisterX11Cookie(x11FakeCookie, true);

			try
			{
				cm.closeChannel(cn, "Closed due to user request", true);
			}
			catch (IOException ignored)
			{
			}
		}
	}

	/**
	 * Sets the receive window size.
	 * <p>
	 * The receive window is a maximum number of bytes that the remote side can send to this channel without
	 * waiting for us to consume them (AKA "in-flight bytes").
	 * <p>
	 * When your connection is over a large-latency/high-bandiwdth network, specifying a bigger value
	 * allows the network to be efficiently utilized. OTOH, if you don't drain this channel quickly enough
	 * all those bytes in flight can end up getting buffered.
	 * <p>
	 * This value can be adjusted at runtime.
	 *
	 * @param newSize the new size
	 */
	public synchronized void setWindowSize(int newSize) {
        cn.setWindowSize(newSize);
    }
}
