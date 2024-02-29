package com.trilead.ssh2.jenkins;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.trilead.ssh2.log.Logger;

/**
 * Class for filtering algorithms.
 * The reason for this filter is that some algorithms have security issues.
 * The filter can be disabled by setting the system property {@link #isEnabledFilterProperty} to false.
 * The list of algorithms to filter can be set by setting the system property {@link #filteredAlgorithmsProperty}.
 */
public class FilterAlgorithms {
    /**
     * The system property suffix to enable/disable the filter.
     */
    private static final String ALGORITHMS = ".algorithms";
    /**
     * The system property suffix to set the list of algorithms to filter.
     */
    private static final String ENABLED = ".enabled";
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(FilterAlgorithms.class);
    /**
     * The system property to enable/disable the filter.
     */
    private final String isEnabledFilterProperty;
    /**
     * The system property to set the list of algorithms to filter.
     */
    private final String filteredAlgorithmsProperty;

    /**
     * The list of algorithms to filter.
     */
    private List<String> filteredAlgorithms = new ArrayList<>();

    /**
     * Constructor.
     * @param clazz the class name used for the system properties
     * @param filteredAlgorithms the list of algorithms to filter
     */
    public FilterAlgorithms(String clazz, List<String> filteredAlgorithms) {
        this.filteredAlgorithms = filteredAlgorithms;
        this.isEnabledFilterProperty = clazz + ENABLED;
        this.filteredAlgorithmsProperty = clazz + ALGORITHMS;
    }

    /**
     * Filter algorithms.
     * @param algorithms the algorithms to filter
     * @return the filtered algorithms
     */
    public String[] filter(String[] algorithms) {
        String[] ret = Collections.emptySet().toArray(new String[0]);
        if (algorithms != null) {
            if (!isEnabled()) {
                LOGGER.log(20, "Algorithms filter is disabled");
                ret = algorithms;
            } else {
                ret = Arrays.stream(algorithms)
                        .filter(x -> !getFilteredAlgorithms().contains(x))
                        .toArray(String[]::new);
            }
        } else {
            LOGGER.log(20, "Algorithms is null");
        }
        return ret;
    }

    /**
     * Check if the filter is enabled.
     * @return true if the filter is enabled
     */
    private boolean isEnabled() {
        return Boolean.parseBoolean(System.getProperty(isEnabledFilterProperty, "true"));
    }

    /**
     * Get the list of algorithms to filter.
     * @return the list of algorithms to filter
     */
    private List<String> getFilteredAlgorithms() {
        List<String> ret = new ArrayList<>();
        if (System.getProperty(filteredAlgorithmsProperty) != null && !System.getProperty(filteredAlgorithmsProperty).isEmpty()) {
            ret = Arrays.asList(System.getProperty(filteredAlgorithmsProperty).split(","));
        } else {
            ret = filteredAlgorithms;
        }
        return ret;
    }

    public String getIsEnabledFilterProperty() {
        return isEnabledFilterProperty;
    }

    public String getFilteredAlgorithmsProperty() {
        return filteredAlgorithmsProperty;
    }
}
