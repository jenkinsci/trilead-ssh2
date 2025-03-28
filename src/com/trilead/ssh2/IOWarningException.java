package com.trilead.ssh2;

import java.io.IOException;
import java.io.Serial;

/**
 * @author Thomas Singer
 */
public final class IOWarningException extends IOException {

    @Serial
    private static final long serialVersionUID = 1L;
    
	// Setup ==================================================================

    public IOWarningException(String message) {
		super(message);
	}
}
