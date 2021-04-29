package com.proxy.controllers;

import bftsmart.communication.client.ReplyListener;
import bftsmart.tom.RequestContext;
import bftsmart.tom.core.messages.TOMMessage;
import java.util.concurrent.CompletableFuture;

public class ReplyListenerImp<T> implements ReplyListener {

    private final CompletableFuture<T> reply;
    private int numReplies;

    public ReplyListenerImp(CompletableFuture<T> reply) {
        this.reply = reply;
        this.numReplies = 0;
    }

    @Override
    public void reset() {

    }



    @Override
    public void replyReceived(RequestContext requestContext, TOMMessage tomMessage) {
        numReplies++;
        System.out.println("Hello " + numReplies);
        if(numReplies == 4) {
            reply.complete((T) tomMessage.getContent());
        }

    }
}
