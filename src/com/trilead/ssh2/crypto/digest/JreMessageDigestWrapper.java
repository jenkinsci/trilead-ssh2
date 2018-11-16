package com.trilead.ssh2.crypto.digest;

import java.security.MessageDigest;

/**
 * @author Michael Clarke
 */
public class JreMessageDigestWrapper implements Digest {

    private final MessageDigest digest;

    public JreMessageDigestWrapper(MessageDigest digest) {
        super();
        this.digest = digest;
    }

    public int getDigestLength() {
        return digest.getDigestLength();
    }

    public void update(byte b) {
        digest.update(b);
    }

    public void update(byte[] b) {
        digest.update(b);
    }

    public void update(byte[] b, int off, int len) {
        digest.update(b, off, len);
    }

    public void reset() {
        digest.reset();
    }

    public void digest(byte[] out) {
        byte[] output = digest.digest();
        System.arraycopy(output, 0, out, 0, out.length);
    }

    public void digest(byte[] out, int off) {
        byte[] output = digest.digest();
        System.arraycopy(output, 0, out, off, out.length);

    }
}
