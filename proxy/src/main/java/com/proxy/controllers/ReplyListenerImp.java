package com.proxy.controllers;

import bftsmart.communication.client.ReplyListener;
import bftsmart.reconfiguration.ViewManager;
import bftsmart.tom.RequestContext;
import bftsmart.tom.core.messages.TOMMessage;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ReplyListenerImp<T> implements ReplyListener {

    private final CompletableFuture<T> reply;
    private int numReplies;
    private int quorumSize;
    private final Map<String, Integer> hashes;
    private boolean finished;

    public ReplyListenerImp(CompletableFuture<T> reply, int quorumSize) {
        this.reply = reply;
        this.numReplies = 0;
        this.quorumSize = quorumSize;
        this.hashes = new HashMap<>(quorumSize);
        this.finished = false;
    }

    @Override
    public void reset() {

    }

    @Override
    public void replyReceived(RequestContext requestContext, TOMMessage tomMessage) {
        String hash = Utils.toHex(tomMessage.getContent());
        numReplies++;

        if (numReplies >= quorumSize && !finished) {
            finished = true;
            reply.complete((T) tomMessage.getContent());

        }

        /*
        System.out.println(numReplies);
        synchronized (hashes) {
            Integer hashCount = hashes.get(hash);
            if (hashCount == null)
                hashes.put(hash, 0);
            else
                hashes.put(hash, ++hashCount);

            if (numReplies >= quorumSize && !finished) {
                System.out.println("Hello");
                for (String h : hashes.keySet()) {
                    int count = hashes.get(h);
                    System.out.println("Count: " + count);
                    if (count >= quorumSize && !finished) {
                        System.out.println("Hello1");
                        finished = true;
                        reply.complete((T) tomMessage.getContent());
                    }
                }
            }
        }*/

    }
}
