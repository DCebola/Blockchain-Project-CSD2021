package com.proxy.controllers;

import bftsmart.communication.client.ReplyListener;
import bftsmart.tom.RequestContext;
import bftsmart.tom.core.messages.TOMMessage;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;

public class ReplyListenerImp implements ReplyListener {

    private final CompletableFuture<String> reply;
    private int numReplies;

    public ReplyListenerImp(CompletableFuture<String> reply) {
        this.reply = reply;
        this.numReplies = 0;
    }

    @Override
    public void reset() {

    }



    @Override
    public void replyReceived(RequestContext requestContext, TOMMessage tomMessage) {
        numReplies++;

        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(tomMessage.getContent());
            ObjectInput objIn = new ObjectInputStream(byteIn);
            if (!objIn.readBoolean()) {
                //logger.info("BAD REQUEST. Proposed transaction: ({}, {}, {})", transaction.getOrigin(), transaction.getDestination(), transaction.getAmount());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else {
                //logger.info("OK. {} transferred {} coins to {}.", transaction.getOrigin(), transaction.getAmount(), transaction.getDestination());
                System.out.println("Reply received");
                if(numReplies == 4) {
                    reply.complete("I am done.");
                }

            }
        } catch (IOException | ResponseStatusException e) {
            e.printStackTrace();
        }


    }
}
