package com.trilead.ssh2.channel;

import java.io.InputStream;

/**
 *
 * @author Kohsuke Kawaguchi
 */
class RingBuffer {
    private byte[] ring;
    private final int sz;
    private final Object lock;

    /**
     * Point to the position in the array where the next read/write would occur.
     *
     * r==w means the buffer is empty.
     */
    private int w,r;

    /**
     * Set to true when the writer closes the write end.
     */
    private boolean closed;

    RingBuffer(int len) {
        this(null,len);
    }

    RingBuffer(Object lock, int len) {
        // to differentiate empty buffer vs full buffer, we need one more byte
        sz = len + 1;
        this.ring = new byte[sz];
        this.lock = lock==null ? this : lock;
    }

    /**
     * Number of bytes readable
     *
     * @return [0,sz) = [0,len]
     */
    int readable() {
        synchronized (lock) {
            return mod(w - r);
        }
    }

    /**
     * Number of bytes writable
     *
     * @return [0,sz) = [0,len]
     */
    int writable() {
        synchronized (lock) {
            return (sz-1)-readable(); // we can't fill the last byte to differentiate full buffer vs empty buffer
        }
    }

    private int mod(int i) {
        assert i>=-sz;
        return i>=0 ? i%sz : (i+sz)%sz;
    }

    /**
     * Like {@link #mod(int)}, except we know the parameter is never negative.
     */
    private int modp(int i) {
        assert i>=0;
        return i%sz;
    }

    public void write(byte[] buf, int start, int len) throws InterruptedException {
        while (len>0) {
            int chunk;

            synchronized (lock) {
                while ((chunk = Math.min(len,writable()))==0)
                    lock.wait();

                chunk = Math.min(chunk,sz-w);   // limit the write to one continuous region

                System.arraycopy(buf,start,ring,w,chunk);
                w=modp(w+chunk);

                lock.notifyAll();
            }

            start += chunk;
            len -= chunk;
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
            ring = null;
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

                chunk = Math.min(chunk,sz-r);   // limit the read to one continuous region

                System.arraycopy(ring,r,buf,start,chunk);
                r=modp(r+chunk);

                lock.notifyAll();
            }

            start += chunk;
            len -= chunk;
            read += chunk;
        }
    }
}
