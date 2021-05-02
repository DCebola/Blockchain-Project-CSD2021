package com.proxy.controllers;

import bftsmart.communication.client.ReplyListener;
import bftsmart.tom.RequestContext;
import bftsmart.tom.core.messages.TOMMessage;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ReplyListenerImp<T> implements ReplyListener {

    private final CompletableFuture<T> reply;
    private ObjectInput objectInput;
    private int numReplies;
    private final int quorumSize;
    private final Map<String, Integer> hashes;

    public ReplyListenerImp(CompletableFuture<T> reply, int quorumSize) {
        this.objectInput = null;
        this.reply = reply;
        this.numReplies = 0;
        this.quorumSize = quorumSize;
        this.hashes = new HashMap<>(quorumSize);
    }

    @Override
    public void reset() {

    }

    @Override
    public void replyReceived(RequestContext requestContext, TOMMessage tomMessage) {
        numReplies++;
        try {
            objectInput = new ObjectInputStream(new ByteArrayInputStream(tomMessage.getContent()));
            String hashOperation = Utils.toHex((byte[]) objectInput.readObject());
            System.out.println(hashOperation);
            Integer hashCount = hashes.get(hashOperation);
            if (hashCount == null)
                hashes.put(hashOperation, 1);
            else
                hashes.put(hashOperation, ++hashCount);

            if (hashes.get(hashOperation) == quorumSize)
                reply.complete((T) tomMessage.getContent());

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
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
