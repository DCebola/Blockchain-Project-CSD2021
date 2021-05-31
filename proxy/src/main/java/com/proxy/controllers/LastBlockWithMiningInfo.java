package com.proxy.controllers;

import java.io.Serializable;

public class LastBlockWithMiningInfo implements Serializable {

    private final Block lastMinedBlock;
    private final BlockHeader blockHeader;

    private static final long serialVersionUID = 6529655044467727690L;

    public LastBlockWithMiningInfo() {
        this.lastMinedBlock = null;
        this.blockHeader = null;
    }

    public LastBlockWithMiningInfo(Block lastMinedBlock, BlockHeader blockHeader) {
        this.lastMinedBlock = lastMinedBlock;
        this.blockHeader = blockHeader;
    }

    public Block getLastMinedBlock() {
        return lastMinedBlock;
    }

    public BlockHeader getBlockHeader() {
        return blockHeader;
    }
}
