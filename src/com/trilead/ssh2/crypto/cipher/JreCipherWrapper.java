package com.trilead.ssh2.crypto.cipher;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * BlockCipher that delegates cryptographic operations to {@code javax.crypt.Cipher}.
 */
public class JreCipherWrapper implements BlockCipher {

    public static JreCipherWrapper getInstance(String algorithm, AlgorithmParameterSpec parameterSpec) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            return new JreCipherWrapper(cipher, parameterSpec);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private final Cipher cipher;
    private final String algorithm;
    private final AlgorithmParameterSpec parameterSpec;

    private JreCipherWrapper(Cipher cipher, AlgorithmParameterSpec parameterSpec) {
        this.cipher = cipher;
        this.parameterSpec = parameterSpec;
        String alg = cipher.getAlgorithm();
        this.algorithm = alg.contains("/") ? alg.substring(0, alg.indexOf('/')) : alg;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        int mode = forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        try {
            cipher.init(mode, new SecretKeySpec(key, algorithm), parameterSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public void init(boolean forEncryption, KeySpec keySpec)  {
        int mode = forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
            SecretKey key = factory.generateSecret(keySpec);
            cipher.init(mode, key, parameterSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public int getBlockSize() {
        return cipher.getBlockSize();
    }

    @Override
    public void transformBlock(byte[] src, int srcoff, byte[] dst, int dstoff) {
        try {
            cipher.update(src, srcoff, cipher.getBlockSize(), dst, dstoff);
        } catch (ShortBufferException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
