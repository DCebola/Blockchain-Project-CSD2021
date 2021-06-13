package com.clients;

import java.io.Serializable;

public class BlockHeaderAndReward implements Serializable {

    private final BlockHeader blockHeader;
    private final Transaction reward;

    private static final long serialVersionUID = 6345655068467727690L;

    public BlockHeaderAndReward() {
        this.blockHeader = null;
        this.reward = null;
    }

    public BlockHeaderAndReward(BlockHeader blockHeader, Transaction reward) {
        this.blockHeader = blockHeader;
        this.reward = reward;
    }

    public BlockHeader getBlockHeader() {
        return blockHeader;
    }

    public Transaction getReward() {
        return reward;
    }

}


