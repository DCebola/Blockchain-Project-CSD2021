package com.proxy.controllers;

import java.io.Serializable;
import java.util.List;

public class Block implements Serializable {

    private static final long serialVersionUID = 152968899267765429L;
    private final BlockHeader blockHeader;
    private final List<ValidTransaction> signedTransactions;

    public Block() {
        this.blockHeader = null;
        this.signedTransactions = null;
    }

    public Block(BlockHeader blockHeader, List<ValidTransaction> signedTransactions) {
        this.blockHeader = blockHeader;
        this.signedTransactions = signedTransactions;

    }


    public BlockHeader getBlockHeader() {
        return blockHeader;
    }

    public List<ValidTransaction> getSignedTransactions() {
        return signedTransactions;
    }
}