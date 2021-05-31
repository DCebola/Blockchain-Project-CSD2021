package com.clients;

import java.io.Serializable;

public class BlockHeaderAndReward implements Serializable {

    private final BlockHeader blockHeader;
    private final Transaction transaction;

    private static final long serialVersionUID = 6345655068467727690L;

    public BlockHeaderAndReward() {
        this.blockHeader = null;
        this.transaction = null;
    }

    public BlockHeaderAndReward(BlockHeader blockHeader, Transaction transaction) {
        this.blockHeader = blockHeader;
        this.transaction = transaction;
    }

    public BlockHeader getBlockHeader() {
        return blockHeader;
    }

    public Transaction getTransaction() {
        return transaction;
    }

}

