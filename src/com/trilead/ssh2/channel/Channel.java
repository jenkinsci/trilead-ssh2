
package com.trilead.ssh2.channel;

import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.PacketSignal;
import com.trilead.ssh2.packets.PacketWindowChange;
import com.trilead.ssh2.packets.Packets;
import com.trilead.ssh2.transport.TransportManager;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;

import static com.trilead.ssh2.util.IOUtils.closeQuietly;

/**
 * Channel.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: Channel.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */
public class Channel
{
	/*
	 * OK. Here is an important part of the JVM Specification:
	 * (http://java.sun.com/docs/books/vmspec/2nd-edition/html/Threads.doc.html#22214)
	 * 
	 * Any association between locks and variables is purely conventional.
	 * Locking any lock conceptually flushes all variables from a thread's
	 * working memory, and unlocking any lock forces the writing out to main
	 * memory of all variables that the thread has assigned. That a lock may be
	 * associated with a particular object or a class is purely a convention.
	 * (...)
	 * 
	 * If a thread uses a particular shared variable only after locking a
	 * particular lock and before the corresponding unlocking of that same lock,
	 * then the thread will read the shared value of that variable from main
	 * memory after the lock operation, if necessary, and will copy back to main
	 * memory the value most recently assigned to that variable before the
	 * unlock operation.
	 * 
	 * This, in conjunction with the mutual exclusion rules for locks, suffices
	 * to guarantee that values are correctly transmitted from one thread to
	 * another through shared variables.
	 * 
	 * ====> Always keep that in mind when modifying the Channel/ChannelManger
	 * code.
	 * 
	 */

	static final int STATE_OPENING = 1;
	static final int STATE_OPEN = 2;
	static final int STATE_CLOSED = 4;

	private static final int CHANNEL_BUFFER_SIZE = Integer.getInteger(
			Channel.class.getName()+".bufferSize",
			1024*1024 + 16*1024).intValue();

    /**
     * This channel's session size.
     */
    // @GuarydedBy("this")
    int channelBufferSize = CHANNEL_BUFFER_SIZE;

	/*
	 * To achieve correctness, the following rules have to be respected when
	 * accessing this object:
	 */

	// These fields can always be read
	final ChannelManager cm;
	final ChannelOutputStream stdinStream;

    /**
     * One stream.
     *
     * Either {@link #stream} and {@link #buffer} is set, or the {@link #sink} is set, but those
     * are mutually exclusive. The former is used when we are buffering data and let the application
     * read it via {@link InputStream}, and the latter is used when we are passing through the data
     * to another {@link OutputStream}.
     *
     * The synchronization is done by {@link Channel}
     */
    class Output {
        ChannelInputStream stream;
        FifoBuffer buffer = new FifoBuffer(Channel.this, 2048, channelBufferSize);
        OutputStream sink;

        public void write(byte[] buf, int start, int len) throws IOException {
            if (buffer!=null) {
                try {
                    buffer.write(buf,start,len);
                } catch (InterruptedException e) {
                    throw new InterruptedIOException();
                }
            } else {
                sink.write(buf,start,len);
                freeupWindow(len, true);
            }
        }

        /**
         * How many bytes can be read from the buffer?
         */
        public int readable() {
            if (buffer!=null)   return buffer.readable();
            else                return 0;
        }

        /**
         * See {@link InputStream#available()}
         */
        public int available() {
            if (buffer==null)
                throw new IllegalStateException("Output is being piped to "+sink);

            int sz = buffer.readable();
            if (sz>0)    return sz;
            return isEOF() ? -1 : 0;
        }

        /**
         * Read from the buffer.
         */
        public int read(byte[] buf, int start, int len) throws InterruptedException {
            return buffer.read(buf,start,len);
        }

        /**
         * Called when there will be no more data arriving to this output any more.
         * Not that buffer might still have some more data that needs to be drained.
         */
        public void eof() {
            if (buffer!=null)
                buffer.close();
            else
                closeQuietly(sink);
        }

        /**
         * Instead of spooling data, let our I/O thread write to the given {@link OutputStream}.
         */
        public void pipeTo(OutputStream os) throws IOException {
            sink = os;
            if (buffer.readable()!=0) {
                freeupWindow(buffer.writeTo(os));
            }

            buffer = null;
            stream = null;
        }
    }

    final Output stdout = new Output();
    final Output stderr = new Output();

    // These two fields will only be written while the Channel is in state
	// STATE_OPENING.
	// The code makes sure that the two fields are written out when the state is
	// changing to STATE_OPEN.
	// Therefore, if you know that the Channel is in state STATE_OPEN, then you
	// can read these two fields without synchronizing on the Channel. However, make
	// sure that you get the latest values (e.g., flush caches by synchronizing on any
	// object). However, to be on the safe side, you can lock the channel.

	int localID = -1;
	int remoteID = -1;

	/*
	 * Make sure that we never send a data/EOF/WindowChange msg after a CLOSE
	 * msg.
	 * 
	 * This is a little bit complicated, but we have to do it in that way, since
	 * we cannot keep a lock on the Channel during the send operation (this
	 * would block sometimes the receiver thread, and, in extreme cases, can
	 * lead to a deadlock on both sides of the connection (senders are blocked
	 * since the receive buffers on the other side are full, and receiver
	 * threads wait for the senders to finish). It all depends on the
	 * implementation on the other side. But we cannot make any assumptions, we
	 * have to assume the worst case. Confused? Just believe me.
	 */

	/*
	 * If you send a message on a channel, then you have to aquire the
	 * "channelSendLock" and check the "closeMessageSent" flag (this variable
	 * may only be accessed while holding the "channelSendLock" !!!
	 * 
	 * BTW: NEVER EVER SEND MESSAGES FROM THE RECEIVE THREAD - see explanation
	 * above.
	 */

	final Object channelSendLock = new Object();
	boolean closeMessageSent = false;

	/*
	 * Stop memory fragmentation by allocating this often used buffer.
	 * May only be used while holding the channelSendLock
	 */

	final byte[] msgWindowAdjust = new byte[9];

	// If you access (read or write) any of the following fields, then you have
	// to synchronize on the channel.

	int state = STATE_OPENING;

	boolean closeMessageRecv = false;

	/* This is a stupid implementation. At the moment we can only wait
	 * for one pending request per channel.
	 */
	int successCounter = 0;
	int failedCounter = 0;

	int localWindow = 0; /* locally, we use a small window, < 2^31 */
	long remoteWindow = 0; /* long for readable  2^32 - 1 window support */

	int localMaxPacketSize = -1;
	int remoteMaxPacketSize = -1;


    private boolean eof = false;

    synchronized void eof() {
        stdout.eof();
        stderr.eof();
        eof = true;
    }
    boolean isEOF() {
        return eof;
    }

	Integer exit_status;

	String exit_signal;

	// we keep the x11 cookie so that this channel can be closed when this
	// specific x11 forwarding gets stopped

	String hexX11FakeCookie;

	// reasonClosed is special, since we sometimes need to access it
	// while holding the channelSendLock.
	// We protect it with a private short term lock.

	private final Object reasonClosedLock = new Object();
	private Throwable reasonClosed = null;

	public Channel(ChannelManager cm)
	{
		this.cm = cm;

		this.localWindow = channelBufferSize;
		this.localMaxPacketSize = TransportManager.MAX_PACKET_SIZE - 1024; // leave enough slack

		this.stdinStream = new ChannelOutputStream(this);
		this.stdout.stream = new ChannelInputStream(this, false);
		this.stderr.stream = new ChannelInputStream(this, true);
	}

	/* Methods to allow access from classes outside of this package */

    public synchronized void setWindowSize(int newSize) {
        if (newSize<=0)  throw new IllegalArgumentException("Invalid value: "+newSize);
        this.channelBufferSize = newSize;
        // next time when the other side sends us something, we'll issue SSH_MSG_CHANNEL_WINDOW_ADJUST
    }

	public ChannelInputStream getStderrStream()
	{
		return stderr.stream;
	}

	public ChannelOutputStream getStdinStream()
	{
		return stdinStream;
	}

	public ChannelInputStream getStdoutStream()
	{
		return stdout.stream;
	}

    public synchronized void pipeStdoutStream(OutputStream os) throws IOException {
        stdout.pipeTo(os);
    }

    public synchronized void pipeStderrStream(OutputStream os) throws IOException {
        stderr.pipeTo(os);
    }

	public String getExitSignal()
	{
		synchronized (this)
		{
			return exit_signal;
		}
	}

	public Integer getExitStatus()
	{
		synchronized (this)
		{
			return exit_status;
		}
	}

    /**
     * Gets reason closed.
     *
     * @return the reason closed
     * @deprecated Use       {@link #getReasonClosedCause()}
     */
    public String getReasonClosed()
	{
		synchronized (reasonClosedLock)
		{
			return reasonClosed!=null ? reasonClosed.getMessage() : null;
		}
	}

    public Throwable getReasonClosedCause()
   	{
   		synchronized (reasonClosedLock)
   		{
   			return reasonClosed;
   		}
   	}

	public void setReasonClosed(String reasonClosed)
	{
        setReasonClosed(new IOException(reasonClosed));
	}

    public void setReasonClosed(Throwable reasonClosed) {
        synchronized (reasonClosedLock)
      		{
      			if (this.reasonClosed == null)
      				this.reasonClosed = reasonClosed;
      		}
    }

    /**
     * Update the flow control couner and if necessary, sends ACK to the other end to
     * let it send more data.
     */
    void freeupWindow(int copylen) throws IOException {
        freeupWindow(copylen, false);
	}

    /**
     * Update the flow control couner and if necessary, sends ACK to the other end to
     * let it send more data.
     */
    void freeupWindow(int copylen, boolean sendAsync) throws IOException {
        if (copylen <= 0) return;

        int increment = 0;
        int remoteID;
        int localID;

        synchronized (this) {
            if (localWindow <= ((channelBufferSize * 3) / 4)) {
                // have enough local window been consumed? if so, we'll send Ack

                // the window control is on the combined bytes of stdout & stderr
                int space = channelBufferSize - stdout.readable() - stderr.readable();

                increment = space - localWindow;
                if (increment > 0)    // increment<0 can't happen, but be defensive
                    localWindow += increment;
            }

            remoteID = this.remoteID; /* read while holding the lock */
            localID = this.localID; /* read while holding the lock */

        }

        /*
         * If a consumer reads stdout and stdin in parallel, we may end up with
         * sending two msgWindowAdjust messages. Luckily, it
         * does not matter in which order they arrive at the server.
         */

        if (increment > 0)
        {
            if (log.isEnabled())
                log.log(80, "Sending SSH_MSG_CHANNEL_WINDOW_ADJUST (channel " + localID + ", " + increment + ")");

            synchronized (channelSendLock)
            {
                byte[] msg = msgWindowAdjust;

                msg[0] = Packets.SSH_MSG_CHANNEL_WINDOW_ADJUST;
                msg[1] = (byte) (remoteID >> 24);
                msg[2] = (byte) (remoteID >> 16);
                msg[3] = (byte) (remoteID >> 8);
                msg[4] = (byte) (remoteID);
                msg[5] = (byte) (increment >> 24);
                msg[6] = (byte) (increment >> 16);
                msg[7] = (byte) (increment >> 8);
                msg[8] = (byte) (increment);

                if (closeMessageSent == false) {
                    if (sendAsync) {
                        cm.tm.sendAsynchronousMessage(msg);
                    } else {
                        cm.tm.sendMessage(msg);
                    }
                }
            }
        }
    }

    public void requestWindowChange(int term_width_characters, int term_height_characters,
                                    int term_width_pixels, int term_height_pixels) throws IOException {
        PacketWindowChange pwc;

        synchronized (this) {
            if (state != Channel.STATE_OPEN)
                throw (IOException)new IOException("Cannot request window-change on this channel").initCause(getReasonClosedCause());

            pwc = new PacketWindowChange(remoteID, term_width_characters, term_height_characters,
                    term_width_pixels, term_height_pixels);
        }

        synchronized (channelSendLock) {
            if (closeMessageSent)
                throw (IOException)new IOException("Cannot request window-change on this channel").initCause(getReasonClosedCause());
            cm.tm.sendMessage(pwc.getPayload());
        }
    }

    public void signal(String name) throws IOException {
        PacketSignal p;

        synchronized (this) {
            if (state != Channel.STATE_OPEN)
                throw (IOException)new IOException("Cannot send signal on this channel").initCause(getReasonClosedCause());

            p = new PacketSignal(remoteID, name);
        }

        synchronized (channelSendLock) {
            if (closeMessageSent)
                throw (IOException)new IOException("Cannot request window-change on this channel").initCause(getReasonClosedCause());
            cm.tm.sendMessage(p.getPayload());
        }
    }

    private static final Logger log = Logger.getLogger(Channel.class);
}
