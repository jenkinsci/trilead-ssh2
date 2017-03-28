package com.trilead.ssh2.signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * @author Michael Clarke
 */
public final class KeyAlgorithmManager {

    private static final Collection<KeyAlgorithm<PublicKey, PrivateKey>> supportedAlgorithms = buildSupportAlgorithmsList();

    private KeyAlgorithmManager() {
        super();
        // static access only
    }

    public static Collection<KeyAlgorithm<PublicKey, PrivateKey>> getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    private static Collection<KeyAlgorithm<PublicKey, PrivateKey>> buildSupportAlgorithmsList() {
        List<KeyAlgorithm<?, ?>> algorithms = new ArrayList<>();

        algorithms.add(new RSAKeyAlgorithm());
        algorithms.add(new DSAKeyAlgorithm());

        return (Collection) Collections.unmodifiableCollection(algorithms);
    }
}
