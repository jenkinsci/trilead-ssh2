/*
 * The MIT License
 *
 * Copyright (c) 2004-, all the contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.trilead.ssh2.jenkins;

import com.trilead.ssh2.SFTPv3Client;
import com.trilead.ssh2.Connection;
import com.trilead.ssh2.SFTPv3FileHandle;
import com.trilead.ssh2.SFTPv3FileAttributes;
import com.trilead.ssh2.SFTPException;
import com.trilead.ssh2.sftp.ErrorCodes;

import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;

/**
 * This Class adds file manage capabilities to the SFTPv3Client class.
 * @author Kohsuke Kawaguchi
 */
public class SFTPClient extends SFTPv3Client {
    public SFTPClient(Connection conn) throws IOException {
        super(conn);
    }

    /**
     * Checks if the given path exists.
     * @param path directory or file path.
     * @return true if it exists.
     * @throws IOException if it is not possible to access to the directory or file .
     */
    public boolean exists(String path) throws IOException {
        return _stat(path)!=null;
    }

    /**
     * Graceful {@link #stat(String)} that returns null if the path doesn't exist.
     * @param path directory path.
     *             @throws IOException if it is not possible to access to the directory.
     */
    public SFTPv3FileAttributes _stat(String path) throws IOException {
        try {
            return stat(path);
        } catch (SFTPException e) {
            int c = e.getServerErrorCode();
            if (c==ErrorCodes.SSH_FX_NO_SUCH_FILE || c==ErrorCodes.SSH_FX_NO_SUCH_PATH)
                return null;
            else
                throw e;
        }
    }

    /**
     * Makes sure that the directory exists, by creating it if necessary.
     * @param path directory path.
     * @param posixPermission POSIX permissions.
     * @throws IOException if it is not possible to access to the directory.
     */
    public void mkdirs(String path, int posixPermission) throws IOException {
        SFTPv3FileAttributes atts = _stat(path);
        if (atts!=null && atts.isDirectory())
            return;

        int idx = path.lastIndexOf('/');
        if (idx>0)
            mkdirs(path.substring(0,idx), posixPermission);

        try {
            mkdir(path, posixPermission);
        } catch (IOException e) {
            throw new IOException("Failed to mkdir "+path,e);
        }
    }

    /**
     *
     * @param path file path.
     * @return Creates a new file and return an OutputStream to writes to it.
     * @throws IOException if it is not possible to access to the file.
     */
    public OutputStream writeToFile(String path) throws IOException {
        final SFTPv3FileHandle h = createFile(path);
        return new SFTPOutputStream(h);
    }

    /**
     *
     * @param file file path.
     * @return return an InputStream to the file.
     * @throws IOException if it is not possible to access to the file.
     */
    public InputStream read(String file) throws IOException {
        final SFTPv3FileHandle h = openFileRO(file);
        return new SFTPInputStream(h);
    }

    /**
     * Change file or directory permissions.
     * @param path file or directory path.
     * @param permissions POSIX permissions.
     * @throws IOException in case of error.
     */
    public void chmod(String path, int permissions) throws IOException {
        SFTPv3FileAttributes atts = new SFTPv3FileAttributes();
        atts.permissions = permissions;
        setstat(path, atts);
    }

    private class SFTPOutputStream extends OutputStream {
        private final SFTPv3FileHandle h;
        private long offset;

        public SFTPOutputStream(SFTPv3FileHandle h) {
            this.h = h;
            offset = 0;
        }

        public void write(int b) throws IOException {
            write(new byte[]{(byte)b});
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            SFTPClient.this.write(h,offset,b,off,len);
            offset += len;
        }

        @Override
        public void close() throws IOException {
            closeFile(h);
        }
    }

    private class SFTPInputStream extends InputStream {
        private final SFTPv3FileHandle h;
        private long offset;

        public SFTPInputStream(SFTPv3FileHandle h) {
            this.h = h;
            offset = 0;
        }

        public int read() throws IOException {
            byte[] b = new byte[1];
            if(read(b)<0)
                return -1;
            return b[0];
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int r = SFTPClient.this.read(h,offset,b,off,len);
            if (r<0)    return -1;
            offset += r;
            return r;
        }

        @Override
        public long skip(long n) throws IOException {
            offset += n;
            return n;
        }

        @Override
        public void close() throws IOException {
            closeFile(h);
        }
    }
}
