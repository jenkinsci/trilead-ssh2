package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.CertificateDecoder;
import com.trilead.ssh2.crypto.PEMStructure;
import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.cipher.BlockCipherFactory;
import com.trilead.ssh2.crypto.cipher.CBCMode;
import com.trilead.ssh2.crypto.cipher.DES;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.mindrot.jbcrypt.BCrypt;

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
    
    private static final String ED25519_KEY_NAME = "ssh-ed25519";
    private static final String ED25519_CURVE_NAME = "Ed25519";
    
    protected ED25519KeyAlgorithm() {
        /*Whilst the signature is 'NoneWith', it actually uses a digest from the key's parameter specification
         * so is really SHA512WithEdDSA, but has to be looked up using what's in the Provider implementation.
         */
        super("NoneWithEdDSA", ED25519_KEY_NAME, EdDSAPrivateKey.class, new EdDSASecurityProvider());
    }
    
    @Override
    public byte[] encodeSignature(byte[] signature) throws IOException {
        TypesWriter signatureWriter = new TypesWriter();
        signatureWriter.writeString(ED25519_KEY_NAME);
        signatureWriter.writeString(signature, 0, signature.length);
        return signatureWriter.getBytes();
    }
    
    @Override
    public byte[] decodeSignature(byte[] encodedSignature) throws IOException {
        TypesReader typesReader = new TypesReader(encodedSignature);
    
        String signatureFormat = typesReader.readString();
        if (!signatureFormat.equals(ED25519_KEY_NAME)) {
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
        typesWriter.writeString(ED25519_KEY_NAME);
        typesWriter.writeString(encoded, 0, encoded.length);
        return typesWriter.getBytes();
    }
    
    @Override
    public EdDSAPublicKey decodePublicKey(byte[] encodedPublicKey) throws IOException {
        TypesReader typesReader = new TypesReader(encodedPublicKey);
    
        String keyFormat = typesReader.readString();
        if (!keyFormat.equals(ED25519_KEY_NAME)) {
            throw new IOException("Invalid key type");
        }
    
        byte[] keyBytes = typesReader.readByteString();
        if (0 != typesReader.remain()) {
            throw new IOException("Unexpected padding in public key");
        }
    
        return new EdDSAPublicKey(new EdDSAPublicKeySpec(keyBytes, EdDSANamedCurveTable.getByName(ED25519_CURVE_NAME)));
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
            byte[] kdfOptions = pemReader.readByteString();
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

                TypesReader kdfReader = new TypesReader(kdfOptions);
                byte[] salt = kdfReader.readByteString();
                int rounds = kdfReader.readUINT32();
                SshCipher sshCipher = SshCipher.getInstance(cipher);
                privateKeys = decryptData(privateKeys, generateKayAndIvPbkdf2(password.getBytes(StandardCharsets.UTF_8), salt, rounds, sshCipher.getKeyLength(), sshCipher.getBlockSize()), sshCipher);
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
            if (!keyType.equals(ED25519_KEY_NAME)) {
                throw new IOException("Invalid key type");
            }
    
            byte[] publicBytes = privateKeyTypeReader.readByteString();
            byte[] privateBytes = privateKeyTypeReader.readByteString();
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(ED25519_CURVE_NAME);
            
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

        private static byte[] decryptData(byte[] encryptedData, byte[] keyAndIv, SshCipher sshCipher) {
            byte[] key = new byte[sshCipher.getKeyLength()];
            byte[] iv = new byte[sshCipher.getBlockSize()];

            System.arraycopy(keyAndIv, 0, key, 0, key.length);
            System.arraycopy(keyAndIv, key.length, iv, 0, iv.length);

            BlockCipher cipher = sshCipher.createBlockCipher(key, iv, false);

            byte[] decrypted = new byte[encryptedData.length];
            for (int i = 0; i < encryptedData.length / cipher.getBlockSize(); i++) {
                cipher.transformBlock(encryptedData, i * cipher.getBlockSize(), decrypted, i * cipher.getBlockSize());
            }

            return decrypted;

        }

        private static byte[] generateKayAndIvPbkdf2(byte[] password, byte[] salt, int rounds, int keyLength, int ivLength) {
            byte[] keyAndIV = new byte[keyLength + ivLength];
            new BCrypt().pbkdf(password, salt, rounds, keyAndIV);
            return keyAndIV;
        }

        private enum SshCipher {

            DESEDE_CBC(24, 8, "des-ede3-cbc") {
                @Override
                BlockCipher createBlockCipher(byte[] key, byte[] iv, boolean encrypt) {
                    return BlockCipherFactory.createCipher("3des-cbc", encrypt, key, iv);
                }
            },
            DES_CBC(8, 8,"des-cbc") {
                @Override
                BlockCipher createBlockCipher(byte[]key, byte[] iv, boolean encrypt) {
                    DES des = new DES();
                    des.init(encrypt, key);
                    return new CBCMode(des, iv, encrypt);
                }
            },
            AES128_CBC(16, 16, "aes-128-cbc", "aes128-cbc") {
                @Override
                BlockCipher createBlockCipher(byte[] key, byte[] iv, boolean encrypt) {
                    return BlockCipherFactory.createCipher("aes128-cbc", encrypt, key, iv);
                }
            },
            AES192_CBC(24, 16, "aes-192-cbc", "aes192-cbc") {
                @Override
                BlockCipher createBlockCipher(byte[] key, byte[] iv, boolean encrypt) {
                    return BlockCipherFactory.createCipher("aes192-cbc", encrypt, key, iv);
                }
            },
            AES256_CBC(32, 16, "aes-256-cbc", "aes256-cbc") {
                @Override
                BlockCipher createBlockCipher(byte[] key, byte[] iv, boolean encrypt) {
                    return BlockCipherFactory.createCipher("aes256-cbc", encrypt, key, iv);
                }
            };

            private final String[] sshCipherNames;
            private final int keyLength;
            private final int blockSize;

            SshCipher(int keyLength, int blockSize, String cipherName, String... cipherAliases) {
                this.keyLength = keyLength;
                this.blockSize = blockSize;
                String[] sshCipherNames = new String[1 + (null == cipherAliases ? 0 : cipherAliases.length)];
                sshCipherNames[0] = cipherName;
                if (null != cipherAliases) {
                    System.arraycopy(cipherAliases, 0, sshCipherNames, 1, cipherAliases.length);
                }
                this.sshCipherNames = sshCipherNames;
            }

            abstract BlockCipher createBlockCipher(byte[] key, byte[] iv, boolean encrypt);

            public int getBlockSize() {
                return blockSize;
            }

            public int getKeyLength() {
                return keyLength;
            }

            public static SshCipher getInstance(String cipher) {
                for (SshCipher instance : values()) {
                    for (String name : instance.sshCipherNames) {
                        if (name.equalsIgnoreCase(cipher)) {
                            return instance;
                        }
                    }
                }
                throw new IllegalArgumentException("Unknown Cipher: " + cipher);
            }

        }
    
    
    }

}
