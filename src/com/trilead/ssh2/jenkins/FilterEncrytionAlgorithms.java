package com.trilead.ssh2.jenkins;

import java.util.Collections;
import java.util.List;

/**
 * Filter encryption algorithms.
 * The reason for this filter is that some algorithms have security issues.
 * The filter can be disabled by setting the system property
 * com.trilead.ssh2.jenkins.FilterEncrytionAlgorithms.enabled to false.
 * The list of algorithms to filter can be set by setting the system property
 * com.trilead.ssh2.jenkins.FilterEncrytionAlgorithms.algorithms (e.g. type01,type02,type03).
 */
public class FilterEncrytionAlgorithms {
    /*
     * The list of algorithms to filter by default.
     */
    private static final List<String> filteredAlgorithms = Collections.emptyList();

    /**
     * Filter algorithms.
     * @param algorithms The algorithms to filter.
     * @return The filtered algorithms.
     */
    public static String[] filter(String[] algorithms) {
        FilterAlgorithms filter = new FilterAlgorithms(FilterEncrytionAlgorithms.class.getName(), filteredAlgorithms);
        return filter.filter(algorithms);
    }
}
