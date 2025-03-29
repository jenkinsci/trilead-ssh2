package com.trilead.ssh2.auth;

import java.util.Collection;

public interface AgentProxy {
    /*
     * 2025-03-19: Steven Jubb: Original method signature did not use a parameterized Collection. For the sake of
     * strict-tying, it has been updated from below:
     * public Collection getIdentities();
     */
    public Collection<AgentIdentity> getIdentities();
}
