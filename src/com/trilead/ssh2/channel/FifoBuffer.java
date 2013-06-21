package com.trilead.ssh2.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * FIFO buffer for a reader thread and a writer thread to collaborate.
 *
 * Unlike a ring buffer, which uses a fixed memory regardless of the number of bytes currently in the buffer,
 * this implementation uses a single linked list to reduce the memory footprint when the reader
 * closely follows the writer, regardless of the capacity limit set in the constructor.
 *
 * In trilead, the writer puts the data we receive from the network, and the user code acts as a reader.
 * A user code normally drains the buffer more quickly than what the network delivers, so this implementation
 * saves memory while simultaneously allowing us to advertise a bigger window size for a large latency network.
 *
 * @author Kohsuke Kawaguchi
 */
class FifoBuffer {
    /**
     * Unit of buffer, singly linked and lazy created as needed.
     */
    static final class Page {
        final byte[] buf;
        Page next;

        Page(int sz) {
            this.buf = new byte[sz];
        }
    }

    /**
     * Points to a specific byte in a {@link Page}.
     */
    class Pointer {
        Page p;
        /**
         * [0,p.buf.size)
         */
        int off;

        Pointer(Page p, int off) {
            this.p = p;
            this.off = off;
        }

        /**
         * Figure out the number of bytes that can be read/written in one array copy.
         */
        private int chunk() {
            int sz = pageSize-off;
            assert sz>=0;

            if (sz>0)   return sz;

            Page q = p.next;
            if (q==null)
                q = p.next = newPage();
            p = q;
            off = 0;
            return pageSize;
        }

        public void write(byte[] buf, int start, int len) {
            while (len>0) {
                int chunk = Math.min(len,chunk());
                System.arraycopy(buf,start,p.buf,off,chunk);

                off+=chunk;
                len-=chunk;
                start+=chunk;
            }
        }

        public void read(byte[] buf, int start, int len) {
            while (len>0) {
                int chunk = Math.min(len,chunk());
                System.arraycopy(p.buf,off,buf,start,chunk);

                off+=chunk;
                len-=chunk;
                start+=chunk;
            }
        }
    }

    private final Object lock;

    /**
     * Number of bytes currently in this ring buffer
     */
    private int sz;
    /**
     * Cap to the # of bytes that we can hold.
     */
    private int limit;
    private final int pageSize;

    /**
     * The position at which the next read/write will happen.
     */
    private Pointer r,w;

    /**
     * Set to true when the writer closes the write end.
     */
    private boolean closed;

    FifoBuffer(int pageSize, int limit) {
        this(null,pageSize,limit);
    }

    FifoBuffer(Object lock, int pageSize, int limit) {
        this.lock = lock==null ? this : lock;
        this.limit = limit;
        this.pageSize = pageSize;

        Page p = newPage();
        r = new Pointer(p,0);
        w = new Pointer(p,0);
    }

    public void setLimit(int newLimit) {
        synchronized (lock) {
            limit = newLimit;
        }
    }

    private Page newPage() {
        return new Page(pageSize);
    }

    /**
     * Number of bytes readable
     */
    int readable() {
        synchronized (lock) {
            return sz;
        }
    }

    /**
     * Number of bytes writable
     */
    int writable() {
        return Math.max(0,limit-readable());
    }

    public void write(byte[] buf, int start, int len) throws InterruptedException {
        while (len>0) {
            int chunk;

            synchronized (lock) {
                while ((chunk = Math.min(len,writable()))==0)
                    lock.wait();

                w.write(buf, start, chunk);

                start += chunk;
                len -= chunk;
                sz += chunk;

                lock.notifyAll();
            }
        }
    }

    public void close() {
        synchronized (lock) {
            if (!closed) {
                closed = true;
                releaseRing();
                lock.notifyAll();
            }
        }
    }

    /**
     * If the ring is no longer needed, release the buffer.
     */
    private void releaseRing() {
        if (closed &&  readable()==0)
            r = w = null;
    }

    /**
     *
     * @see InputStream#read(byte[],int,int)
     */
    public int read(byte[] buf, int start, int len) throws InterruptedException {
        if (len==0)     return 0;

        int read = 0;   // total # of bytes read

        while (true) {
            int chunk;

            synchronized (lock) {
                while (true) {
                    chunk = Math.min(len,readable());
                    if (chunk>0)    break;

                    // there's nothing we can immediately read

                    if (read>0)     return read;    // we've already read some

                    if (closed) {
                        releaseRing();
                        return -1;  // no more data
                    }
                    lock.wait(); // wait until the writer gives us something
                }

                r.read(buf,start,chunk);

                start += chunk;
                len -= chunk;
                read += chunk;
                sz -= chunk;

                lock.notifyAll();
            }
        }
    }

    /**
     * Write whatever readable to the specified OutputStream, then return.
     */
    public int writeTo(OutputStream out) throws IOException {
        try {
            int total = 0;
            while (readable()>0) {
                byte[] buf = new byte[1024];    // most often this method gets called before we have any data, so this is a win
                int read = read(buf, 0, buf.length);
                out.write(buf,0,read);
                total += read;
            }
            return total;
        } catch (InterruptedException e) {
            throw new AssertionError(e); // we carefully read only what we can read without blocking
        }
    }
}
