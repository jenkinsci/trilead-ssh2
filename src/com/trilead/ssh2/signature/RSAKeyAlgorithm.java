package com.trilead.ssh2.signature;

import com.trilead.ssh2.IOWarningException;
import com.trilead.ssh2.crypto.CertificateDecoder;
import com.trilead.ssh2.crypto.PEMStructure;
import com.trilead.ssh2.crypto.SimpleDERReader;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

/**
 * @author Michael Clarke
 */
public class RSAKeyAlgorithm extends KeyAlgorithm<RSAPublicKey, RSAPrivateKey> {

    public RSAKeyAlgorithm() {
        super("SHA1WithRSA", "ssh-rsa", RSAPrivateKey.class);
    }

    @Override
    public byte[] encodeSignature(byte[] signature) throws IOException {
        final TypesWriter tw = new TypesWriter();

        tw.writeString(getKeyFormat());

		/* S is NOT an MPINT. "The value for 'rsa_signature_blob' is encoded as a string
		 * containing s (which is an integer, without lengths or padding, unsigned and in
		 * network byte order)."
		 */


		/* Remove first zero sign byte, if present */

        if ((signature.length > 1) && (signature[0] == 0x00)) {
            tw.writeString(signature, 1, signature.length - 1);
        } else {
            tw.writeString(signature, 0, signature.length);
        }

        return tw.getBytes();
    }

    @Override
    public byte[] decodeSignature(byte[] encodedSignature) throws IOException {
        final TypesReader tr = new TypesReader(encodedSignature);

        final String sig_format = tr.readString();

        if (!sig_format.equals(getKeyFormat())) {
            throw new IOException("Peer sent wrong signature format");
        }

		/* S is NOT an MPINT. "The value for 'rsa_signature_blob' is encoded as a string
		 * containing s (which is an integer, without lengths or padding, unsigned and in
		 * network byte order)." See also below.
		 */

        final byte[] s = tr.readByteString();

        if (s.length == 0) {
            throw new IOException("Error in RSA signature, S is empty.");
        }

        if (tr.remain() != 0) {
            throw new IOException("Padding in RSA signature!");
        }

        return s;
    }

    @Override
    public byte[] encodePublicKey(RSAPublicKey publicKey) throws IOException {
        final TypesWriter tw = new TypesWriter();

        tw.writeString(getKeyFormat());
        tw.writeMPInt(publicKey.getPublicExponent());
        tw.writeMPInt(publicKey.getModulus());

        return tw.getBytes();
    }

    @Override
    public RSAPublicKey decodePublicKey(byte[] encodedPublicKey) throws IOException {
        final TypesReader tr = new TypesReader(encodedPublicKey);

        final String key_format = tr.readString();
        if (!key_format.equals(getKeyFormat())) {
            throw new IOWarningException("Unsupported key format found '" + key_format + "' while expecting " + getKeyFormat());
        }

        final BigInteger e = tr.readMPINT();
        final BigInteger n = tr.readMPINT();

        if (tr.remain() != 0) {
            throw new IOException("Padding in RSA public key!");
        }

        try {
            final KeyFactory generator = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) generator.generatePublic(new RSAPublicKeySpec(n, e));
        } catch (GeneralSecurityException ex) {
            throw new IOException("Could not generate RSA key", ex);
        }
    }

    @Override
    public List<CertificateDecoder> getCertificateDecoders() {
        return Arrays.asList(new RSACertificateDecoder(), new OpenSshCertificateDecoder("ssh-rsa") {
            @Override
            KeyPair generateKeyPair(TypesReader typesReader) throws GeneralSecurityException, IOException {
                BigInteger n = typesReader.readMPINT();
                BigInteger e = typesReader.readMPINT();
                BigInteger d = typesReader.readMPINT();

                BigInteger c = typesReader.readMPINT();
                BigInteger p = typesReader.readMPINT();


                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
                RSAPrivateKeySpec privateKeySpec;

                if (null == p || null == c) {
                    privateKeySpec = new RSAPrivateKeySpec(n, d);
                } else {
                    BigInteger q = c.modInverse(p);
                    BigInteger pE = d.mod(p.subtract(BigInteger.ONE));
                    BigInteger qE = d.mod(q.subtract(BigInteger.ONE));
                    privateKeySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, pE, qE, c);
                }

                KeyFactory factory = KeyFactory.getInstance("RSA");
                return new KeyPair(factory.generatePublic(publicKeySpec), factory.generatePrivate(privateKeySpec));
            }
        });
    }


    private static class RSACertificateDecoder extends CertificateDecoder {

        @Override
        public String getStartLine() {
            return "-----BEGIN RSA PRIVATE KEY-----";
        }

        @Override
        public String getEndLine() {
            return "-----END RSA PRIVATE KEY-----";
        }

        @Override
        protected KeyPair createKeyPair(PEMStructure pemStructure) throws IOException {
            SimpleDERReader dr = new SimpleDERReader(pemStructure.getData());

            byte[] seq = dr.readSequenceAsByteArray();

            if (dr.available() != 0)
                throw new IOException("Padding in RSA PRIVATE KEY DER stream.");

            dr.resetInput(seq);

            BigInteger version = dr.readInt();

            if ((version.compareTo(BigInteger.ZERO) != 0) && (version.compareTo(BigInteger.ONE) != 0))
                throw new IOException("Wrong version (" + version + ") in RSA PRIVATE KEY DER stream.");

            BigInteger n = dr.readInt();
            BigInteger e = dr.readInt();
            BigInteger d = dr.readInt();
            BigInteger p = dr.readInt();
            BigInteger q = dr.readInt();
            BigInteger pE = dr.readInt();
            BigInteger qE = dr.readInt();
            BigInteger c = dr.readInt();

            try {
                RSAPrivateKeySpec privateKeySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, pE, qE, c);
                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
                PublicKey publicKey = factory.generatePublic(publicKeySpec);
                return new KeyPair(publicKey, privateKey);
            } catch (GeneralSecurityException ex) {
                throw new IOException("Could not decode RSA Key Pair");
            }
        }
    }
}
