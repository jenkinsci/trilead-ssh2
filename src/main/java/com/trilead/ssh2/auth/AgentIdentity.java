package com.trilead.ssh2.auth;

public interface AgentIdentity {
    public String getAlgName();
    public byte[] getPublicKeyBlob();
    public byte[] sign(byte[] data);
}
