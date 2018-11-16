package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.CertificateDecoder;
import com.trilead.ssh2.crypto.PEMStructure;
import com.trilead.ssh2.crypto.SimpleDERReader;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.List;

/**
 * @author Michael Clarke
 */
public abstract class ECDSAKeyAlgorithm extends KeyAlgorithm<ECPublicKey, ECPrivateKey> {

    private static final String ECDSA_SHA2_PREFIX = "ecdsa-sha2-";

    private static final byte ANS1_INTEGER = 0x02;
    private static final byte ANS1_ZERO = 0x00;

    private final String curveName;
    private final ECParameterSpec ecParameterSpec;

    private ECDSAKeyAlgorithm(String signatureAlgorithm, String curveName, ECParameterSpec ecParameterSpec) {
        super(signatureAlgorithm, ECDSA_SHA2_PREFIX + curveName, ECPrivateKey.class);
        this.curveName = curveName;
        this.ecParameterSpec = ecParameterSpec;
    }

    /*package*/ String getCurveName() {
        return curveName;
    }

    /*package*/ ECParameterSpec getEcParameterSpec() {
        return  ecParameterSpec;
    }

    @Override
    public ECPublicKey decodePublicKey(byte[] key) throws IOException
    {
        TypesReader tr = new TypesReader(key);

        String keyFormat = tr.readString();
        if (!keyFormat.equals(getKeyFormat())) {
            throw new IOException("Invalid key format");
        }

        /*
        We need to read the next block, but don't do anything with it:
        the curve name is part of the key format which we've already checked above
         */
        /*String curveName = */tr.readString();
        byte[] groupBytes = tr.readByteString();

        if (tr.remain() != 0) {
            throw new IOException("Unexpected adding in ECDSA public key");
        }

        ECParameterSpec params = getEcParameterSpec();
        ECPoint group = decodePoint(groupBytes, params.getCurve());
        if (null == group) {
            throw new IOException("Invalid ECDSA group");
        }


        try {
            KeySpec keySpec = new ECPublicKeySpec(group, params);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return (ECPublicKey) kf.generatePublic(keySpec);
        } catch (GeneralSecurityException ex) {
            throw new IOException("Could not decode ECDSA key", ex);
        }
    }

    @Override
    public byte[] encodePublicKey(ECPublicKey key) throws IOException {

        byte[] encodedPoint = encodePoint(key.getW(), key.getParams().getCurve());

        TypesWriter tw = new TypesWriter();
        tw.writeString(getKeyFormat());
        tw.writeString(getCurveName());
        tw.writeString(encodedPoint, 0, encodedPoint.length);

        return tw.getBytes();
    }


    @Override
    public byte[] decodeSignature(byte[] encodedSignature) throws IOException {

        TypesReader typesReader = new TypesReader(encodedSignature);

        String signatureFormat = typesReader.readString();
        if (!signatureFormat.equals(getKeyFormat())) {
            throw new IOException("Unsupported signature format: " + signatureFormat);
        }

        byte[] rAndS = typesReader.readByteString();

        if (typesReader.remain() != 0) {
            throw new IOException("Unexpected padding in ECDSA signature");
        }

        TypesReader rsReader = new TypesReader(rAndS);
        byte[] r = rsReader.readMPINT().toByteArray();
        byte[] s = rsReader.readMPINT().toByteArray();

        int rLength = r.length;
        int sLength = s.length;

        if ((r[0] & 0x80) != 0) {
            rLength++;
        }

        if ((s[0] & 0x80) != 0) {
            sLength++;
        }

        int totalLength = 6 + rLength + sLength;
        ByteArrayOutputStream os = new ByteArrayOutputStream(totalLength);

        os.write(0x30);

        writeLength(totalLength - 2, os);

        os.write(ANS1_INTEGER);
        writeLength(rLength, os);
        if (rLength != r.length) {
            os.write(ANS1_ZERO);
        }
        os.write(r);

        os.write(ANS1_INTEGER);
        writeLength(sLength, os);
        if (sLength != s.length) {
            os.write(ANS1_ZERO);
        }
        os.write(s);

        return os.toByteArray();
    }

    private static void writeLength(int length, OutputStream os) throws IOException {
        if (length <= 0x7F) {
            os.write(length);
            return;
        }

        int numOctets = 0;
        int lenCopy = length;
        while (lenCopy != 0) {
            lenCopy >>>= 8;
            numOctets++;
        }

        os.write(0x80 | numOctets);

        for (int i = (numOctets - 1) * 8; i >= 0; i -= 8) {
            os.write((byte) (length >> i));
        }
    }

    @Override
    public byte[] encodeSignature(byte[] sig) throws IOException {
        SimpleDERReader reader = new SimpleDERReader(new SimpleDERReader(sig).readSequenceAsByteArray());
        BigInteger r = reader.readInt();
        BigInteger s = reader.readInt();

        TypesWriter rAndSWriter = new TypesWriter();
        rAndSWriter.writeMPInt(r);
        rAndSWriter.writeMPInt(s);

        byte[] encoded = rAndSWriter.getBytes();

        TypesWriter typesWriter = new TypesWriter();
        typesWriter.writeString(getKeyFormat());
        typesWriter.writeString(encoded, 0, encoded.length);
        return typesWriter.getBytes();
    }

    @Override
    public boolean supportsKey(PrivateKey originalKey) {
        if (!(originalKey instanceof ECPrivateKey)) {
            return false;
        }
        ECPrivateKey key = (ECPrivateKey) originalKey;
        return super.supportsKey(key) && key.getParams().getCurve().getField().getFieldSize() == getEcParameterSpec().getCurve().getField().getFieldSize();
    }

    private static ECPoint decodePoint(byte[] encodedPoint, EllipticCurve curve) {
        int elementSize = (curve.getField().getFieldSize() + 7) / 8;
        if (encodedPoint.length != 2 * elementSize + 1 || encodedPoint[0] != 0x04 || encodedPoint.length == 0) {
            return null;
        }

        byte[] xPoint = new byte[elementSize];
        System.arraycopy(encodedPoint, 1, xPoint, 0, elementSize);
        byte[] yPoint = new byte[elementSize];
        System.arraycopy(encodedPoint, 1 + elementSize, yPoint, 0, elementSize);

        return new ECPoint(new BigInteger(1, xPoint), new BigInteger(1, yPoint));
    }

    private static byte[] encodePoint(ECPoint group, EllipticCurve curve) {
        int elementSize = (curve.getField().getFieldSize() + 7) / 8;
        byte[] encodedPoint = new byte[2 * elementSize + 1];

        encodedPoint[0] = 0x04;

        byte[] affineX = removeLeadingZeroes(group.getAffineX().toByteArray());
        System.arraycopy(affineX, 0, encodedPoint, 1 + elementSize - affineX.length, affineX.length);
        byte[] affineY = removeLeadingZeroes(group.getAffineY().toByteArray());
        System.arraycopy(affineY, 0, encodedPoint, 1 + elementSize + elementSize - affineY.length, affineY.length);

        return encodedPoint;
    }

    private static byte[] removeLeadingZeroes(byte[] input) {
        if (input[0] != ANS1_ZERO) {
            return input;
        }

        int pos = 1;
        while (pos < input.length - 1 && input[pos] == ANS1_ZERO) {
            pos++;
        }

        byte[] output = new byte[input.length - pos];
        System.arraycopy(input, pos, output, 0, output.length);
        return output;
    }


    public static class ECDSASha2Nistp256 extends ECDSAKeyAlgorithm {

        public ECDSASha2Nistp256() {
            super("SHA256withECDSA", "nistp256",
                    new ECParameterSpec(
                        new EllipticCurve(
                            new ECFieldFp(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
                            new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
                            new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
                        ),
                        new ECPoint(
                            new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
                            new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
                        ),
                        new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
                    1)
            );
        }

        @Override
        public List<CertificateDecoder> getCertificateDecoders() {
            return Arrays.asList(new EcdsaCertificateDecoder("1.2.840.10045.3.1.7", getEcParameterSpec()),
                    new OpenSshEcdsaCertificateDecoder(getKeyFormat(), getCurveName(), getEcParameterSpec()));
        }
    }

    public static class ECDSASha2Nistp384 extends ECDSAKeyAlgorithm {

        public ECDSASha2Nistp384() {
            super("SHA384withECDSA", "nistp384",
                    new ECParameterSpec(
                        new EllipticCurve(
                            new ECFieldFp(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16)),
                            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16),
                            new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16)
                        ),
                        new ECPoint(
                            new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16),
                            new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16)
                        ),
                        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
                    1)
            );
        }

        @Override
        public List<CertificateDecoder> getCertificateDecoders() {
            return Arrays.asList(new EcdsaCertificateDecoder("1.3.132.0.34", getEcParameterSpec()),
                    new OpenSshEcdsaCertificateDecoder(getKeyFormat(), getCurveName(), getEcParameterSpec()));
        }
    }

    public static class ECDSASha2Nistp521 extends ECDSAKeyAlgorithm {

        public ECDSASha2Nistp521() {
            super("SHA512withECDSA", "nistp521",
                    new ECParameterSpec(
                        new EllipticCurve(
                            new ECFieldFp(new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)),
                            new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16),
                            new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16)
                        ),
                        new ECPoint(
                            new BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
                            new BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16)
                        ),
                        new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
                    1)
            );
        }

        @Override
        public List<CertificateDecoder> getCertificateDecoders() {
            return Arrays.asList(new EcdsaCertificateDecoder("1.3.132.0.35", getEcParameterSpec()),
                    new OpenSshEcdsaCertificateDecoder(getKeyFormat(), getCurveName(), getEcParameterSpec()));
        }

    }


    private static class EcdsaCertificateDecoder extends CertificateDecoder {

        private final String oid;
        private final ECParameterSpec ecParameterSpec;

        private EcdsaCertificateDecoder(String oid, ECParameterSpec ecParameterSpec) {
            super();
            this.oid = oid;
            this.ecParameterSpec = ecParameterSpec;
        }

        @Override
        public String getStartLine() {
            return "-----BEGIN EC PRIVATE KEY-----";
        }

        @Override
        public String getEndLine() {
            return "-----END EC PRIVATE KEY-----";
        }

        @Override
        protected KeyPair createKeyPair(PEMStructure pemStructure) throws IOException {
            SimpleDERReader DERderReader = new SimpleDERReader(pemStructure.getData());

            byte[] sequence = DERderReader.readSequenceAsByteArray();

            if (DERderReader.available() != 0) {
                throw new IOException("Unexpected padding in EC private key");
            }

            SimpleDERReader sequenceReader = new SimpleDERReader(sequence);

            BigInteger version = sequenceReader.readInt();
            if ((version.compareTo(BigInteger.ONE) != 0)) {
                throw new IOException("Unexpected version number in EC private key: " + version);
            }

            byte[] privateBytes = sequenceReader.readOctetString();

            String curveOid = null;
            byte[] publicBytes = null;
            while (sequenceReader.available() > 0) {
                int type = sequenceReader.readConstructedType();
                SimpleDERReader fieldReader = sequenceReader.readConstructed();
                switch (type) {
                    case 0:
                        curveOid = fieldReader.readOid();
                        break;
                    case 1:
                        publicBytes = fieldReader.readOctetString();
                        break;
                }
            }

            if (!oid.equals(curveOid)) {
                throw new IOException("Incorrect OID for current curve");
            }

            BigInteger s = new BigInteger(1, privateBytes);
            byte[] publicBytesSlice = new byte[publicBytes.length - 1];
            System.arraycopy(publicBytes, 1, publicBytesSlice, 0, publicBytesSlice.length);
            ECPoint w = ECDSAKeyAlgorithm.decodePoint(publicBytesSlice, ecParameterSpec.getCurve());

            ECPrivateKeySpec privSpec = new ECPrivateKeySpec(s, ecParameterSpec);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecParameterSpec);

            try {
                KeyFactory factory = KeyFactory.getInstance("EC");
                PublicKey ecPublicKey = factory.generatePublic(pubSpec);
                PrivateKey ecPrivateKey = factory.generatePrivate(privSpec);
                return new KeyPair(ecPublicKey, ecPrivateKey);
            } catch (GeneralSecurityException ex) {
                throw new IOException("Could not generate EC key pair");
            }
        }
    }


    private static class OpenSshEcdsaCertificateDecoder extends OpenSshCertificateDecoder {

        private final String curveName;
        private final ECParameterSpec ecParameterSpec;

        OpenSshEcdsaCertificateDecoder(String keyAlgorithm, String curveName, ECParameterSpec ecParameterSpec) {
            super(keyAlgorithm);
            this.curveName = curveName;
            this.ecParameterSpec = ecParameterSpec;
        }

        @Override
        KeyPair generateKeyPair(TypesReader tr) throws GeneralSecurityException, IOException {
            String curveName = tr.readString();
            if (!curveName.equals(this.curveName)) {
                throw new IOException("Incorrect curve name: " + curveName);
            }
            byte[] groupBytes = tr.readByteString();
            BigInteger privateKey = tr.readMPINT();

            ECPoint group = decodePoint(groupBytes, ecParameterSpec.getCurve());
            if (null == group) {
                throw new IOException("Invalid ECDSA group");
            }


            KeySpec keySpec = new ECPublicKeySpec(group, ecParameterSpec);
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey, ecParameterSpec);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return new KeyPair(kf.generatePublic(keySpec), kf.generatePrivate(privateKeySpec));

        }
    }

}