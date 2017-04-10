package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.CertificateDecoder;
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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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
    public List<CertificateDecoder> getCertificateDecoders() {
        return Collections.singletonList((CertificateDecoder) new OpenSshCertificateDecoder(ED25519KeyAlgorithm.ED25519_KEY_NAME) {
            @Override
            KeyPair generateKeyPair(TypesReader reader) throws GeneralSecurityException, IOException {
                EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(ED25519KeyAlgorithm.ED25519_CURVE_NAME);

                byte[] publicKeyBytes = reader.readByteString();
                byte[] privateKeyBytes = reader.readByteString();

                EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(publicKeyBytes, spec);
                EdDSAPrivateKeySpec privateKeySpec = new EdDSAPrivateKeySpec(Arrays.copyOfRange(privateKeyBytes, 0, 32), spec);

                KeyFactory factory = KeyFactory.getInstance("EdDSA", new EdDSASecurityProvider());
                PublicKey publicKey = factory.generatePublic(publicKeySpec);
                PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
                return new KeyPair(publicKey, privateKey);
            }
        });
    }

}
