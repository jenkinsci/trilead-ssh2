package com.trilead.ssh2.auth;

import java.util.Collection;

public interface AgentProxy {
    Collection<AgentIdentity> getIdentities();
}
