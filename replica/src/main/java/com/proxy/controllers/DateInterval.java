package com.proxy.controllers;

import java.io.Serializable;

public class DateInterval implements Serializable {

    private final String startDate;
    private final String endDate;
    private static final long serialVersionUID = 152968508266657690L;

    public DateInterval(String startDate, String endDate) {
        this.startDate = startDate;
        this.endDate = endDate;
    }

    public DateInterval() {
        this.startDate = "";
        this.endDate = "";
    }

    public String getStartDate() {
        return startDate;
    }

    public String getEndDate() {
        return endDate;
    }
}
