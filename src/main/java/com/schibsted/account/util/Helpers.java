/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.util;

import java.time.Instant;
import java.util.Date;

import static java.time.temporal.ChronoUnit.SECONDS;

/**
 * Collection of utility functions.
 */
public class Helpers {
    /**
     * Transforms a {@link Date} to an {@link Instant}, safely handling {@code null} instances.
     *
     * @param date instance of {@code Date} to transform
     * @return the same time as an {@code Instant}, or {@code null}
     */
    public static Instant toInstant(Date date) {
        if (date == null) {
            return null;
        }
        return Instant.ofEpochMilli(date.getTime()).truncatedTo(SECONDS);
    }

    public static boolean compareIssuer(String expected, String actual) {
        return expected.replaceAll("/$", "").equals(actual.replaceAll("/$", ""));
    }
}
