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
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

/**
 * @author Michael Clarke
 */
public class DSAKeyAlgorithm extends KeyAlgorithm<DSAPublicKey, DSAPrivateKey> {

    public DSAKeyAlgorithm() {
        super("SHA1WithDSA", "ssh-dss", DSAPrivateKey.class);
    }

    @Override
    public byte[] encodeSignature(byte[] signature) throws IOException {
        TypesWriter tw = new TypesWriter();

        tw.writeString(getKeyFormat());

        int index = 3;
        int len = signature[index++] & 0xff;
        byte[] r = new byte[len];
        System.arraycopy(signature, index, r, 0, r.length);

        index += len + 1;
        len = signature[index++] & 0xff;
        byte[] s = new byte[len];
        System.arraycopy(signature, index, s, 0, s.length);


        byte[] a40 = new byte[40];

		/* Patch (unsigned) r and s into the target array. */

        int r_copylen = (r.length < 20) ? r.length : 20;
        int s_copylen = (s.length < 20) ? s.length : 20;

        System.arraycopy(r, r.length - r_copylen, a40, 20 - r_copylen, r_copylen);
        System.arraycopy(s, s.length - s_copylen, a40, 40 - s_copylen, s_copylen);

        tw.writeString(a40, 0, 40);

        return tw.getBytes();
    }

    @Override
    public byte[] decodeSignature(byte[] encodedSignature) throws IOException {
        byte[] rsArray;

        if (encodedSignature.length == 40)
        {
			/* OK, another broken SSH server. */
            rsArray = encodedSignature;
        }
        else
        {
			/* Hopefully a server obeying the standard... */
            TypesReader tr = new TypesReader(encodedSignature);

            String sig_format = tr.readString();

            if (!sig_format.equals(getKeyFormat()))
                throw new IOException("Peer sent wrong signature format");

            rsArray = tr.readByteString();

            if (rsArray.length != 40)
                throw new IOException("Peer sent corrupt signature");

            if (tr.remain() != 0)
                throw new IOException("Padding in DSA signature!");
        }

		/* Remember, s and r are unsigned ints. */

        int i = 0;

        if (rsArray[0] == 0 && rsArray[1] == 0 && rsArray[2] == 0) {
            int j = ((rsArray[i++] << 24) & 0xff000000) | ((rsArray[i++] << 16) & 0x00ff0000)
                    | ((rsArray[i++] << 8) & 0x0000ff00) | ((rsArray[i++]) & 0x000000ff);
            i += j;
            j = ((rsArray[i++] << 24) & 0xff000000) | ((rsArray[i++] << 16) & 0x00ff0000)
                    | ((rsArray[i++] << 8) & 0x0000ff00) | ((rsArray[i++]) & 0x000000ff);
            byte[] tmp = new byte[j];
            System.arraycopy(rsArray, i, tmp, 0, j);
            rsArray = tmp;
        }

        int first = ((rsArray[0] & 0x80) != 0 ? 1 : 0);
        int second = ((rsArray[20] & 0x80) != 0 ? 1 : 0);
        int length = rsArray.length + 6 + first + second;
        byte[] tmp = new byte[length];

        tmp[0] = (byte) 0x30;

        if (rsArray.length != 40) {
            throw new IOException("Peer sent corrupt signature");
        }

        tmp[1] = (byte) 0x2c;
        tmp[1] += first;
        tmp[1] += second;

        tmp[2] = (byte) 0x02;
        tmp[3] = (byte) 0x14;
        tmp[3] += first;

        System.arraycopy(rsArray, 0, tmp, 4 + first, 20);

        tmp[4 + tmp[3]] = (byte) 0x02;
        tmp[5 + tmp[3]] = (byte) 0x14;
        tmp[5 + tmp[3]] += second;

        System.arraycopy(rsArray, 20, tmp, 6 + tmp[3] + second, 20);

        return tmp;
    }

    @Override
    public byte[] encodePublicKey(DSAPublicKey publicKey) throws IOException {
        DSAParams params = publicKey.getParams();

        TypesWriter tw = new TypesWriter();

        tw.writeString(getKeyFormat());
        tw.writeMPInt(params.getP());
        tw.writeMPInt(params.getQ());
        tw.writeMPInt(params.getG());
        tw.writeMPInt(publicKey.getY());

        return tw.getBytes();
    }

    @Override
    public DSAPublicKey decodePublicKey(byte[] encodedPublicKey) throws IOException {
        TypesReader tr = new TypesReader(encodedPublicKey);

        String key_format = tr.readString();
        if (!key_format.equals(getKeyFormat())) {
            throw new IOWarningException("Unsupported key format found '" + key_format + "' while expecting " + getKeyFormat());
        }

        final BigInteger p = tr.readMPINT();
        final BigInteger q = tr.readMPINT();
        final BigInteger g = tr.readMPINT();
        final BigInteger y = tr.readMPINT();

        if (tr.remain() != 0) {
            throw new IOException("Padding in DSA public key!");
        }

        try {
            KeyFactory generator = KeyFactory.getInstance("DSA");
            return (DSAPublicKey) generator.generatePublic(new DSAPublicKeySpec(y, p, q, g));
        } catch (GeneralSecurityException ex) {
            throw new IOException("Could not generate DSA Key", ex);
        }
    }

    @Override
    public List<CertificateDecoder> getCertificateDecoders() {
        return Arrays.asList(new DsaCertificateDecoder(), new OpenSshCertificateDecoder(getKeyFormat()) {
            @Override
            KeyPair generateKeyPair(TypesReader typesReader) throws GeneralSecurityException, IOException {
                BigInteger p = typesReader.readMPINT();
                BigInteger q = typesReader.readMPINT();
                BigInteger g = typesReader.readMPINT();
                BigInteger y = typesReader.readMPINT();
                BigInteger x = typesReader.readMPINT();

                DSAPrivateKeySpec privateKeySpec = new DSAPrivateKeySpec(x, p, q, g);
                DSAPublicKeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);


                KeyFactory factory = KeyFactory.getInstance("DSA");
                PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
                PublicKey publicKey = factory.generatePublic(publicKeySpec);
                return new KeyPair(publicKey, privateKey);
            }
        });
    }

    private static class DsaCertificateDecoder extends CertificateDecoder {

        @Override
        public String getStartLine() {
            return "-----BEGIN DSA PRIVATE KEY-----";
        }

        @Override
        public String getEndLine() {
            return "-----END DSA PRIVATE KEY-----";
        }

        @Override
        protected KeyPair createKeyPair(PEMStructure pemStructure) throws IOException {
            SimpleDERReader dr = new SimpleDERReader(pemStructure.getData());

            byte[] seq = dr.readSequenceAsByteArray();

            if (dr.available() != 0)
                throw new IOException("Padding in DSA PRIVATE KEY DER stream.");

            dr.resetInput(seq);

            BigInteger version = dr.readInt();

            if (version.compareTo(BigInteger.ZERO) != 0)
                throw new IOException("Wrong version (" + version + ") in DSA PRIVATE KEY DER stream.");

            BigInteger p = dr.readInt();
            BigInteger q = dr.readInt();
            BigInteger g = dr.readInt();
            BigInteger y = dr.readInt();
            BigInteger x = dr.readInt();

            if (dr.available() != 0)
                throw new IOException("Padding in DSA PRIVATE KEY DER stream.");

            try {
                DSAPrivateKeySpec privateKeySpec = new DSAPrivateKeySpec(x, p, q, g);
                DSAPublicKeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);
                KeyFactory factory = KeyFactory.getInstance("DSA");
                PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
                PublicKey publicKey = factory.generatePublic(publicKeySpec);
                return new KeyPair(publicKey, privateKey);
            } catch (GeneralSecurityException ex) {
                throw new IOException("Could not decode DSA key pair");
            }

        }
    }
}
