package com.trilead.ssh2.transport;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * We have a dependency to bridge logging from
 * testcontainers SLF4J logs to java.util.logging (JUL).
 * {@code
 * <dependency>
 *   <groupId>org.slf4j</groupId>
 *   <artifactId>slf4j-jdk14</artifactId>
 *   <version>2.0.0</version> <!-- Or the latest version -->
 * </dependency>
* }
* This class only setup JUL and then configures logging
* to console.
 * 
 * 
 */
class JULLoggerSetup {
     public static void setupJULLogger() {
        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.ALL);  // Set global logging level

        // Remove default handlers
        for (var handler : rootLogger.getHandlers()) {
            rootLogger.removeHandler(handler);
        }

        // Add a ConsoleHandler for JUL to print logs to the console
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.ALL);  // Log everything
        consoleHandler.setFormatter(new SimpleFormatter());  // Use simple log format

        // Add the new handler to the root logger
        rootLogger.addHandler(consoleHandler);
    }

}
