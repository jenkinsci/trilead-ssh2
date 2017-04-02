package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.CertificateDecoder;
import com.trilead.ssh2.crypto.PEMStructure;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * @author Michael Clarke
 */
public class ED25519KeyAlgorithm extends KeyAlgorithm<EdDSAPublicKey, EdDSAPrivateKey> {
    
    private static final String ED25519 = "ssh-ed25519";
    
    protected ED25519KeyAlgorithm() {
        /*Whilst the signature is 'NoneWith', it actually uses a digest from the key's parameter specification
         * so is really SHA512WithEdDSA, but has to be looked up using what's in the Provider implementation.
         */
        super("NoneWithEdDSA", ED25519, EdDSAPrivateKey.class, new EdDSASecurityProvider());
    }
    
    @Override
    public byte[] encodeSignature(byte[] signature) throws IOException {
        TypesWriter signatureWriter = new TypesWriter();
        signatureWriter.writeString(ED25519);
        signatureWriter.writeString(signature, 0, signature.length);
        return signatureWriter.getBytes();
    }
    
    @Override
    public byte[] decodeSignature(byte[] encodedSignature) throws IOException {
        TypesReader typesReader = new TypesReader(encodedSignature);
    
        String signatureFormat = typesReader.readString();
        if (!signatureFormat.equals(ED25519)) {
            throw new IOException("Invalid signature format");
        }
    
        byte[] signature = typesReader.readByteString();
        if (typesReader.remain() != 0) {
            throw new IOException("Unexpected padding in signature");
        }
    
        return signature;
    }
    
    @Override
    public byte[] encodePublicKey(EdDSAPublicKey publicKey) throws IOException {
        byte[] encoded = publicKey.getAbyte();

        TypesWriter typesWriter = new TypesWriter();
        typesWriter.writeString(ED25519);
        typesWriter.writeString(encoded, 0, encoded.length);
        return typesWriter.getBytes();
    }
    
    @Override
    public EdDSAPublicKey decodePublicKey(byte[] encodedPublicKey) throws IOException {
        TypesReader typesReader = new TypesReader(encodedPublicKey);
    
        String keyFormat = typesReader.readString();
        if (!keyFormat.equals(ED25519)) {
            throw new IOException("Invalid key type");
        }
    
        byte[] keyBytes = typesReader.readByteString();
        if (0 != typesReader.remain()) {
            throw new IOException("Unexpected padding in public key");
        }
    
        return new EdDSAPublicKey(new EdDSAPublicKeySpec(
                keyBytes, EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512)));
    }
    
    @Override
    public CertificateDecoder getCertificateDecoder() {
        return new OpenSshCertificateDecoder();
    }
    
    private static class OpenSshCertificateDecoder extends CertificateDecoder {
    
        @Override
        public String getStartLine() {
            return "-----BEGIN OPENSSH PRIVATE KEY-----";
        }
    
        @Override
        public String getEndLine() {
            return "-----END OPENSSH PRIVATE KEY-----";
        }
    
        @Override
        public KeyPair createKeyPair(PEMStructure pemStructure) {
            return null;
        }
        
        @Override
        public KeyPair createKeyPair(PEMStructure pemStructure, String password) throws IOException {
            TypesReader pemReader = new TypesReader(pemStructure.getData());
            
            byte[] header = pemReader.readBytes(15);
            if (!"openssh-key-v1".equals(new String(header, StandardCharsets.UTF_8).trim())) {
                throw new IOException("Could not find openssh header in key");
            }
    
            String cipher = pemReader.readString();
            String kdf = pemReader.readString();
            /*byte[] kdfOptions = */pemReader.readByteString(); //not used until we get key decryption sorted
            int keyCount = pemReader.readUINT32();
    
            // I can't actually find any test cases for multiple keys to know how they're used
            if (keyCount != 1) {
                throw new IOException("Only single OpenSSH keys are supported");
            }
    
            /*byte[] publicKeys = */pemReader.readByteString(); //public keys are also stored with each private key, so ignored here and parsed later
            byte[] privateKeys = pemReader.readByteString();
    
            if ("bcrypt".equals(kdf)) {
                if (password == null) {
                    throw new IOException("PEM is encrypted but password has not been specified");
                }

                //TODO handle encrypted keys
                /*
                https://github.com/openssh/openssh-portable/blob/master/openbsd-compat/bcrypt_pbkdf.c
                indicates open-ssh deviates from the normal implementation of bcrypt, so I'll need to check
                whether I can find a Java library that supports this, or whether I have to modify an
                existing implementation... or even write my own.
                 */
                throw new IOException("Encrypted OpenSSH keys are not currently supported");
            } else if (!"none".equals(cipher) || !"none".equals(kdf)) {
                throw new IOException("Unexpected encryption method for key");
            }

            TypesReader privateKeyTypeReader = new TypesReader(privateKeys);
            int checkNumber1 = privateKeyTypeReader.readUINT32();
            int checkNumber2 = privateKeyTypeReader.readUINT32();
    
            if (checkNumber1 != checkNumber2) {
                throw new IOException("Check integers didn't match");
            }
    
            String keyType = privateKeyTypeReader.readString();
            if (!keyType.equals(ED25519)) {
                throw new IOException("Invalid key type");
            }
    
            byte[] publicBytes = privateKeyTypeReader.readByteString();
            byte[] privateBytes = privateKeyTypeReader.readByteString();
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
            
            EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(publicBytes, spec);
            EdDSAPrivateKeySpec privateKeySpec = new EdDSAPrivateKeySpec(Arrays.copyOfRange(privateBytes, 0, 32), spec);
            
            try {
                KeyFactory factory = KeyFactory.getInstance("EdDSA", new EdDSASecurityProvider());
                PublicKey publicKey = factory.generatePublic(publicKeySpec);
                PrivateKey privateKey = factory.generatePrivate(privateKeySpec);


                /*byte[] comment = */privateKeyTypeReader.readByteString(); // we don't need the key name/comment

                for (int i = 0; i < pemReader.remain(); i++) {
                    if (i + 1 != pemReader.readByte()) {
                        throw new IOException("Incorrect padding on private keys");
                    }
                }
    
                return new KeyPair(publicKey, privateKey);
            } catch (GeneralSecurityException ex) {
                throw new IOException("Could not create EcDSA key pair", ex);
            }
        }
    
    
    }

}
