package com.trilead.ssh2.transport;

import org.testcontainers.containers.output.OutputFrame;
import org.testcontainers.containers.output.OutputFrame.OutputType;
import com.trilead.ssh2.log.Logger;
import java.util.function.Consumer;

/**
 * Consumer used to get logging for testcontainers.
 */
 class JulLogConsumer implements Consumer<OutputFrame> {
    private final Logger logger;

    // Constructor to initialize the JUL Logger
    public JulLogConsumer(Logger logger) {
        this.logger = logger;
    }

    @Override
    public void accept(OutputFrame outputFrame) {
        if (outputFrame != null) {
            String message = outputFrame.getUtf8String().trim();  // Get log message
            OutputType type = outputFrame.getType();  // Get output type (STDOUT, STDERR)

            // Map OutputFrame types to appropriate log levels
            if (type == OutputType.STDOUT) {
                logger.log(800,message);  // Standard output as INFO logs
            } else if (type == OutputType.STDERR) {
                logger.log(900,message);  // Standard error as WARNING logs
            } else if (type == OutputType.END) {
                logger.log(1000,"Container log stream closed.");
            }
        }
    }
}
