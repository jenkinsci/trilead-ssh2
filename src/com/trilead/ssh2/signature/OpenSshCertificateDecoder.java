package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.CertificateDecoder;
import com.trilead.ssh2.crypto.PEMStructure;
import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.cipher.BlockCipherFactory;
import com.trilead.ssh2.crypto.cipher.CBCMode;
import com.trilead.ssh2.crypto.cipher.DES;
import com.trilead.ssh2.packets.TypesReader;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

/**
 * An decoder that can read keys written in the 'new' OpenSSH format, generally identified with the header
 * 'BEGIN OPENSSH PRIVATE KEY'.
 * @author Michael Clarke
 */
abstract class OpenSshCertificateDecoder extends CertificateDecoder {

    private final String keyAlgorithm;

    OpenSshCertificateDecoder(String keyAlgorithm) {
        super();
        this.keyAlgorithm = keyAlgorithm;
    }

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

        // I can't actually find any test cases for multiple keys to know how they're used. OpenSSH doesn't even support
        // this case, so I'm not going to look any further for now.
        if (keyCount != 1) {
            throw new IOException("Only single OpenSSH keys are supported");
        }

        /*byte[] publicKeys = */pemReader.readByteString(); //public keys can be parsed from a private key
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
        if (!keyType.equals(keyAlgorithm)) {
            throw new IOException("Invalid key type: " + keyType);
        }

        try {
            KeyPair keyPair = generateKeyPair(privateKeyTypeReader);

            /*byte[] comment = */privateKeyTypeReader.readByteString(); // we don't need the key name/comment

            for (int i = 0; i < pemReader.remain(); i++) {
                if (i + 1 != pemReader.readByte()) {
                    throw new IOException("Incorrect padding on private keys");
                }
            }

            return keyPair;
        } catch (GeneralSecurityException ex) {
            throw new IOException("Could not create key pair", ex);
        }
    }

    abstract KeyPair generateKeyPair(TypesReader typesReader) throws GeneralSecurityException, IOException;

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
        DES_CBC(8, 8, "des-cbc") {
            @Override
            BlockCipher createBlockCipher(byte[] key, byte[] iv, boolean encrypt) {
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
        },
        AES256_CTR(32, 16, "aes-256-ctr", "aes256-ctr") {
            @Override
            BlockCipher createBlockCipher(byte[] key, byte[] iv, boolean encrypt) {
                return BlockCipherFactory.createCipher("aes256-ctr", encrypt, key, iv);
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
