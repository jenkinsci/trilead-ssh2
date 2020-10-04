package com.trilead.ssh2.channel;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 * @author Kohsuke Kawaguchi
 */
public class FifoBufferTest {
    final FifoBuffer rb = new FifoBuffer(9,115);  // use strange number to make buffer mod op interesting
    final byte[] buf = new byte[1024];

    @Test
    public void basic() throws InterruptedException {
        rb.write(new byte[]{1,2,3},0,3);
        rb.close();

        int d = rb.read(buf, 0, 999);
        assertThat(d, is(3));
        assertThat((int)buf[0],is(1));
        assertThat((int)buf[1],is(2));
        assertThat((int)buf[2],is(3));
        assertThat(rb.read(buf, 0, 1), is(-1));
    }

    /**
     * Read/write ops that go around the buffer.
     * <p>
     * Read are smaller so that we leave more stuff in the buffer
     *
     * @throws Exception the exception
     */
    @Test
    public void wrapAround() throws Exception {
        for (int i=0; i<10; i++)
            buf[i] = (byte)(i+1);

        int total=0;
        for (int j=0; j<100; j++) {
            rb.write(buf,0,10);

            byte[] d = new byte[9];
            int dat = rb.read(d, 0, 9);
            assertThat(dat,is(9));

            for (int i=0; i<9; i++) {
                assertThat((int)d[i],is(total+1));
                total = (total+1)%10;
            }
        }
    }

    /**
     * Read/write operation whose buffer is bigger than what the ring buffer holds.
     * This tests the thread notification.
     *
     * @throws Exception the exception
     */
    @Test
    public void bigAccess() throws Exception {
        ExecutorService es = Executors.newFixedThreadPool(1);

        Future<byte[]> reader = es.submit(new Callable<byte[]>() {
            public byte[] call() throws Exception {
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();

                byte[] buf = new byte[1024];
                while (true) {
                    int len = rb.read(buf, 0, buf.length);
                    if (len < 0) return baos.toByteArray();
                    assertTrue(len > 0);
                    baos.write(buf, 0, len);
                }
            }
        });

        byte[] data = new byte[10*1024];
        new Random().nextBytes(data);
        rb.write(data,0,data.length);
        rb.close();

        byte[] copy = reader.get();

        assertArrayEquals(data, copy);

        es.shutdown();
    }
}
