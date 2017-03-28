package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.CertificateDecoder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * @author Michael Clarke
 */
public abstract class KeyAlgorithm<U extends PublicKey, R extends PrivateKey> {

    private final String signatureAlgorithm;
    private final String keyFormat;
    private final Class<R> keyType;

    protected KeyAlgorithm(String signatureAlgorithm, String keyFormat, Class<R> keyType) {
        super();
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyFormat = keyFormat;
        this.keyType = keyType;
    }

    public byte[] generateSignature(byte[] message, R pk, SecureRandom rnd) throws IOException {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(pk, rnd);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException ex) {
            throw new IOException("Could not generate signature");
        }
    }

    public boolean verifySignature(byte[] message, byte[] ds, U dpk) throws IOException {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initVerify(dpk);
            signature.update(message);
            return signature.verify(ds);
        } catch (GeneralSecurityException ex) {
            throw new IOException("Could not verify signature", ex);
        }
    }

    public String getKeyFormat() {
        return keyFormat;
    }

    public abstract byte[] encodeSignature(byte[] signature) throws IOException;

    public abstract byte[] decodeSignature(byte[] encodedSignature) throws IOException;

    public abstract byte[] encodePublicKey(U publicKey) throws IOException;

    public abstract U decodePublicKey(byte[] encodedPublicKey) throws IOException;

    public abstract CertificateDecoder getCertificateDecoder();

    public boolean supportsKey(R key) {
        return keyType.isAssignableFrom(key.getClass());
    }

}
