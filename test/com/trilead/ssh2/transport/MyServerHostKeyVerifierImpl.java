package com.trilead.ssh2.transport;

import com.trilead.ssh2.ServerHostKeyVerifier;

 class MyServerHostKeyVerifierImpl implements ServerHostKeyVerifier{
    
    @Override
    public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm, byte[] serverHostKey) {
        // Always accept any host key (Fake verifier)
        System.out.println("Fake HostKeyVerifier: Host " + hostname + " accepted without verification.");
        return true;
    }

}
