
package com.trilead.ssh2.log;

import com.trilead.ssh2.DebugLogger;

import java.util.logging.Level;

/**
 * Logger - a very simple logger, mainly used during development.
 * Is not based on log4j (to reduce external dependencies).
 * However, if needed, something like log4j could easily be
 * hooked in.
 * <p>
 * For speed reasons, the static variables are not protected
 * with semaphores. In other words, if you dynamicaly change the
 * logging settings, then some threads may still use the old setting.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: Logger.java,v 1.2 2008/03/03 07:01:36 cplattne Exp $
 */

public class Logger
{
	public static boolean enabled = false;
	public static DebugLogger logger = null;
	
	private java.util.logging.Logger log;

	public final static Logger getLogger(Class x)
	{
		return new Logger(x);
	}

	public Logger(Class x)
	{
		this.log = java.util.logging.Logger.getLogger(x.getName());
	}

	public final boolean isEnabled()
	{
		return true;
	}

	public final void log(int lv, String message)
	{
        log.log(level(lv),message);
	}

    public final void log(int lv, String message, Throwable cause)
   	{
       log.log(level(lv),message,cause);
   	}

    private Level level(int lv) {
        if (lv<=20)     return Level.FINE;
        if (lv<=50)     return Level.FINER;
        return Level.FINEST;
    }
}
