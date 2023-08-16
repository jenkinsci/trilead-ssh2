
package com.trilead.ssh2.util;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;


/**
 * TimeoutService (beta). Here you can register a timeout.
 * <p>
 * Implemented having large scale programs in mind: if you open many concurrent SSH connections
 * that rely on timeouts, then there will be only one timeout thread. Once all timeouts
 * have expired/are cancelled, the thread will (sooner or later) exit.
 * Only after new timeouts arrive a new thread (singleton) will be instantiated.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: TimeoutService.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public class TimeoutService {
    
    
    private  ScheduledFuture<?> scheduledFuture;
    private final String hostname;
    private final ThreadFactory threadFactory = new ThreadFactory() {

        @Override
        public Thread newThread(Runnable r) {
            
            String threadName = hostname+"_Trilead_TimeoutService";
            Thread thread = new Thread(r, threadName);
            thread.setDaemon(true);
            return thread;
        }
    };
    private final  ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(threadFactory);
    
    public TimeoutService(String hostname){
        this.hostname = hostname;
    }
    
    


    public class TimeoutToken implements Runnable {
        private Runnable handler;
        private volatile boolean cancelled = false;

        public void run() {
            if (!cancelled) {
                handler.run();
            }
        }
    }

    /**
     * It is assumed that the passed handler will not execute for a long time.
     *
     * @param runTime runTime
     * @param handler handler
     * @return a TimeoutToken that can be used to cancel the timeout.
     */
    public TimeoutToken addTimeoutHandler(long runTime, Runnable handler) {
        TimeoutToken token = new TimeoutToken();
        token.handler = handler;
        long delay = runTime - System.currentTimeMillis();
        if (delay < 0) {
            delay = 0;
        }
        scheduledFuture = scheduler.schedule(token, delay, TimeUnit.MILLISECONDS);
        return token;
    }

    /**
     * Cancel the timeout callback for the specified token.
     *
     * @param token token to be canceled.
     */
    public void cancelTimeoutHandler(TimeoutToken token) {
        token.cancelled = true;
        scheduledFuture.cancel(true);
        scheduler.shutdownNow();
    }
}
