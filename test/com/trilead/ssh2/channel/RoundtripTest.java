package com.trilead.ssh2.channel;

import com.trilead.ssh2.Session;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * @author Kohsuke Kawaguchi
 */
public class RoundtripTest {
    @Rule
    public ConnectionRule con = new ConnectionRule();

    @Test
    public void dataXfer() throws Exception {
        final Session s = con.getConnection().openSession();
        s.execCommand("cat");

        s.getStderr().close();

        ExecutorService es = Executors.newFixedThreadPool(1);
        Future<byte[]> reader = es.submit(new Callable<byte[]>() {
            public byte[] call() throws Exception {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                IOUtils.copy(s.getStdout(), baos);
                return baos.toByteArray();
            }
        });

        byte[] data = new byte[10*1024*1024];
        Random r = new Random();
        r.nextBytes(data);

        int inc;
        for (int i=0; i<data.length; i+=inc) {
            inc = Math.min(data.length-i, r.nextInt(128));
            s.getStdin().write(data,i,inc);
        }
        s.getStdin().close();

        Assert.assertArrayEquals(data, reader.get());
    }
}
