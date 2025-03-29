package com.trilead.ssh2.jenkins;

import java.util.ArrayList;
import java.util.List;

/**
 * Filter host key algorithms.
 * The reason for this filter is that some algorithms have security issues.
 * The filter can be disabled by setting the system property
 * com.trilead.ssh2.jenkins.FilterHostKeyAlgorithms.enabled to false.
 * The list of algorithms to filter can be set by setting the system property
 * com.trilead.ssh2.jenkins.FilterHostKeyAlgorithms.algorithms (e.g. type01,type02,type03).
 */
public class FilterMacAlgorithms {
    /*
     * The list of algorithms to filter.
     */
    private static final List<String> filteredAlgorithms = new ArrayList<>(
        List.of(
                // Terrapin attack see https://en.wikipedia.org/wiki/Terrapin_attack
                "hmac-sha2-512-etm@openssh.com",
                // Terrapin attack see https://en.wikipedia.org/wiki/Terrapin_attack
                "hmac-sha2-256-etm@openssh.com"));

    /**
     * Filter algorithms.
     * @param algorithms The algorithms to filter.
     * @return The filtered algorithms.
     */
    public static String[] filter(String[] algorithms) {
        FilterAlgorithms filter = new FilterAlgorithms(FilterMacAlgorithms.class.getName(), filteredAlgorithms);
        return filter.filter(algorithms);
    }
}
