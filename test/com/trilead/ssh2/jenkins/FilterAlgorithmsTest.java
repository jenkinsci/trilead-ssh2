package com.trilead.ssh2.jenkins;

import static org.junit.Assert.assertArrayEquals;

import java.util.Arrays;

import org.junit.After;
import org.junit.Test;

public class FilterAlgorithmsTest {

    @After
    public void setUp() {
        System.setProperty("foo.enabled", "true");
        System.setProperty("foo.algorithms", "");
    }

    @Test
    public void testFilter() {
        String[] kexAlgorithms = {"algorithm0", "algorithm2", "algorithm3"};
        String[] expected = {"algorithm2", "algorithm3"};
        String[] filteredAlgorithms = {"algorithm0"};
        FilterAlgorithms filter = new FilterAlgorithms("foo",Arrays.asList(filteredAlgorithms));

        assertArrayEquals(expected, filter.filter(kexAlgorithms));
    }

    @Test
    public void testFilterWithNull() {
        String[] expected = {};
        FilterAlgorithms filter = new FilterAlgorithms("foo",null);

        assertArrayEquals(expected, filter.filter(null));
    }

    @Test
    public void testFilterWithEmptyArray() {
        String[] kexAlgorithms = {};
        String[] expected = {};
        FilterAlgorithms filter = new FilterAlgorithms("foo", Arrays.asList(kexAlgorithms));

        assertArrayEquals(expected, filter.filter(kexAlgorithms));
    }

    @Test
    public void testDisabledFilter() {
        String[] kexAlgorithms = {"algorithm0", "algorithm2", "algorithm3"};
        FilterAlgorithms filter = new FilterAlgorithms("foo", Arrays.asList(kexAlgorithms));
        System.setProperty(filter.getIsEnabledFilterProperty(), "false");

        assertArrayEquals(kexAlgorithms, filter.filter(kexAlgorithms));
    }

    @Test
    public void testFilterWithEmptyList() {
        String[] kexAlgorithms = {"algorithm0", "algorithm2", "algorithm3"};
        String[] expected = {};
        FilterAlgorithms filter = new FilterAlgorithms("foo", Arrays.asList(kexAlgorithms));
        System.setProperty(filter.getFilteredAlgorithmsProperty(), "");

        assertArrayEquals(expected, filter.filter(kexAlgorithms));
    }

    @Test
    public void testFilterWithCustomList() {
        String[] kexAlgorithms = {"algorithm0", "algorithm2", "algorithm3"};
        String[] expected = {"algorithm0"};
        FilterAlgorithms filter = new FilterAlgorithms("foo", Arrays.asList(kexAlgorithms));
        System.setProperty(filter.getFilteredAlgorithmsProperty(), "algorithm2,algorithm3");

        assertArrayEquals(expected, filter.filter(kexAlgorithms));
    }

}