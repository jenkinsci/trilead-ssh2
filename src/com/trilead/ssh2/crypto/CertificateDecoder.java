package com.trilead.ssh2.crypto;

import java.io.IOException;
import java.security.KeyPair;

/**
 * @author Michael Clarke
 */
public abstract class CertificateDecoder {

    public abstract String getStartLine();

    public abstract String getEndLine();

    public KeyPair createKeyPair(PEMStructure pemStructure, String password) throws IOException {
        return createKeyPair(pemStructure);
    }
    
    protected abstract KeyPair createKeyPair(PEMStructure pemStructure) throws IOException;
}
