package com.trilead.ssh2.jenkins;

import java.util.ArrayList;
import java.util.List;

import com.trilead.ssh2.log.Logger;

/**
 * Filter KEX algorithms.
 * The reason for this filter is that some algorithms have security issues.
 * The filter can be disabled by setting the system property
 * com.trilead.ssh2.jenkins.FilterKexAlgorithms.enabled to false.
 * The list of algorithms to filter can be set by setting the system property
 * com.trilead.ssh2.jenkins.FilterKexAlgorithms.algorithms (e.g. type01,type02,type03).
 */
public class FilterKexAlgorithms {
    /*
     * The list of algorithms to filter.
     */
    private static final List<String> filteredAlgorithms = new ArrayList<>(
            List.of(
                    // Terrapin attack see https://en.wikipedia.org/wiki/Terrapin_attack
                    "chacha20-poly1305@openssh.com"));

    /**
     * Filter algorithms.
     * @param algorithms The algorithms to filter.
     * @return The filtered algorithms.
     */
    public static String[] filter(String[] algorithms) {
        FilterAlgorithms filter = new FilterAlgorithms(FilterKexAlgorithms.class.getName(), filteredAlgorithms);
        return filter.filter(algorithms);
    }
}
