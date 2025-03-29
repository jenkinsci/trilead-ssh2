package com.trilead.ssh2.jenkins;

import java.util.Collections;
import java.util.List;

/**
 * Filter host key algorithms.
 * The reason for this filter is that some algorithms have security issues.
 * The filter can be disabled by setting the system property
 * com.trilead.ssh2.jenkins.FilterHostKeyAlgorithms.enabled to false.
 * The list of algorithms to filter can be set by setting the system property
 * com.trilead.ssh2.jenkins.FilterHostKeyAlgorithms.algorithms (e.g. type01,type02,type03).
 */
public class FilterHostKeyAlgorithms {
    /*
     * The list of algorithms to filter.
     */
    private static final List<String> filteredAlgorithms = Collections.emptyList();

    /**
     * Filter algorithms.
     * @param algorithms The algorithms to filter.
     * @return The filtered algorithms.
     */
    public static String[] filter(String[] algorithms) {
        FilterAlgorithms filter = new FilterAlgorithms(FilterHostKeyAlgorithms.class.getName(), filteredAlgorithms);
        return filter.filter(algorithms);
    }
}
