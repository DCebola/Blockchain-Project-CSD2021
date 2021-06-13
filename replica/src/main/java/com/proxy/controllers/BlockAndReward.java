package com.proxy.controllers;

import java.io.Serializable;

public class BlockAndReward implements Serializable {

    private final Block block;
    private final SignedTransaction reward;

    private static final long serialVersionUID = 6345655033367727690L;

    public BlockAndReward() {
        this.block = null;
        this.reward = null;
    }

    public BlockAndReward(Block block, SignedTransaction reward) {
        this.block = block;
        this.reward = reward;
    }

    public Block getBlock() {
        return block;
    }

    public SignedTransaction getReward() {
        return reward;
    }
}
