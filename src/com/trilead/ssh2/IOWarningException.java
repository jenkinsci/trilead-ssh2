package com.trilead.ssh2;

import java.io.IOException;

/**
 * @author Thomas Singer
 */
public final class IOWarningException extends IOException {

    private static final long serialVersionUID = 1L;
    
	// Setup ==================================================================

    public IOWarningException(String message) {
		super(message);
	}
}
