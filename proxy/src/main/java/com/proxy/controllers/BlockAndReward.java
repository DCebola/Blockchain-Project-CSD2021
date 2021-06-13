package com.proxy.controllers;

import java.io.Serializable;

public class BlockAndReward implements Serializable {

    private final Block block;
    private final SignedTransaction transaction;

    private static final long serialVersionUID = 6345655033367727690L;

    public BlockAndReward() {
        this.block = null;
        this.transaction = null;
    }

    public BlockAndReward(Block block, SignedTransaction transaction) {
        this.block = block;
        this.transaction = transaction;
    }

    public Block getBlock() {
        return block;
    }

    public SignedTransaction getReward() {
        return transaction;
    }
}
