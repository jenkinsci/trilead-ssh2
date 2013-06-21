package com.trilead.ssh2.util;

import java.io.Closeable;
import java.io.IOException;

/**
 * @author Kohsuke Kawaguchi
 */
public class IOUtils {
    public static void closeQuietly(Closeable c) {
        try {
            c.close();
        } catch (IOException e) {
            // ignore error
        }
    }
}
