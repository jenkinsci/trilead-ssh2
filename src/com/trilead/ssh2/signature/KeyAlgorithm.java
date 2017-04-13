package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.CertificateDecoder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.List;

/**
 * @author Michael Clarke
 */
public abstract class KeyAlgorithm<U extends PublicKey, R extends PrivateKey> {

    private final String signatureAlgorithm;
    private final String keyFormat;
    private final Class<R> keyType;
    private final Provider provider;

    protected KeyAlgorithm(String signatureAlgorithm, String keyFormat, Class<R> keyType) {
        this(signatureAlgorithm, keyFormat, keyType, null);
    }
    
    protected KeyAlgorithm(String signatureAlgorithm, String keyFormat, Class<R> keyType, Provider provider) {
        super();
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyFormat = keyFormat;
        this.keyType = keyType;
        this.provider = provider;
    }

    public byte[] generateSignature(byte[] message, R pk, SecureRandom rnd) throws IOException {
        try {
            Signature signature = (null == provider ? Signature.getInstance(signatureAlgorithm) : Signature.getInstance(signatureAlgorithm, provider));
            signature.initSign(pk, rnd);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException ex) {
            throw new IOException("Could not generate signature", ex);
        }
    }

    public boolean verifySignature(byte[] message, byte[] ds, U dpk) throws IOException {
        try {
            Signature signature = (null == provider ? Signature.getInstance(signatureAlgorithm) : Signature.getInstance(signatureAlgorithm, provider));
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

    public abstract List<CertificateDecoder> getCertificateDecoders();

    public boolean supportsKey(PrivateKey key) {
        return keyType.isAssignableFrom(key.getClass());
    }

}
