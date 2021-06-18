package com.proxy.controllers;

import bftsmart.communication.client.ReplyListener;
import bftsmart.tom.RequestContext;
import bftsmart.tom.core.messages.TOMMessage;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ReplyListenerImp<T> implements ReplyListener {

    private final CompletableFuture<T> reply;
    private ObjectInput objectInput;
    private int numReplies;
    private final int quorumSize;
    private final Map<String, List<Integer>> hashes;

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
        synchronized (this) {
            numReplies++;
            try {
                objectInput = new ObjectInputStream(new ByteArrayInputStream(tomMessage.getContent()));
                int id = objectInput.readInt();
                    byte[] hash = (byte[]) objectInput.readObject();
                    String hashOperation = Utils.toHex(hash);
                    List<Integer> replicas = hashes.get(hashOperation);
                    if (replicas == null) {
                        replicas = new LinkedList<>();
                        hashes.put(hashOperation, replicas);
                    }
                    if (replicas.size() < quorumSize)
                        replicas.add(id);
                    if (replicas.size() == quorumSize) {
                        QuorumResponse op = new QuorumResponse(tomMessage.getContent(), replicas);
                        reply.complete((T) op);
                    }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }
}
