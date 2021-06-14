package com.proxy.controllers;

import java.io.Serializable;

public class PendingReward implements Serializable {

    private final String previousBlockHash;
    private final String rewardId;

    private static final long serialVersionUID = 6346550323394857690L;

    public PendingReward() {
        this.previousBlockHash = null;
        this.rewardId = null;
    }

    public PendingReward(String previousBlockHash, String rewardId) {
        this.previousBlockHash = previousBlockHash;
        this.rewardId = rewardId;
    }

    public String getPreviousBlockHash() {
        return previousBlockHash;
    }

    public String getRewardId() {
        return rewardId;
    }
}
