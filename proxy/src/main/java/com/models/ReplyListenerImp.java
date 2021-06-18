package com.models;

import bftsmart.communication.client.ReplyListener;
import bftsmart.tom.RequestContext;
import bftsmart.tom.core.messages.TOMMessage;
import com.libs.Utils;

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
    private final int[] targets;

    public ReplyListenerImp(CompletableFuture<T> reply, int quorumSize, int[] targets) {
        this.objectInput = null;
        this.reply = reply;
        this.numReplies = 0;
        this.quorumSize = quorumSize;
        this.hashes = new HashMap<>(quorumSize);
        this.targets = targets;
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
                boolean validTarget = false;
                for (int validTargetId : targets) {
                    if (validTargetId == id) {
                        validTarget = true;
                        break;
                    }
                }
                if (validTarget) {
                    System.out.println("Valid target: " + id);
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
                }else{
                    System.out.println("Invalid target: " + id);
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }
}
