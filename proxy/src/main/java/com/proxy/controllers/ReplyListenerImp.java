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

public class ReplyListenerImp implements ReplyListener {

    private final BlockingQueue<Integer> blockingQueue;

    public ReplyListenerImp(BlockingQueue<Integer> blockingQueue) {
        this.blockingQueue = blockingQueue;
    }

    @Override
    public void reset() {

    }



    @Override
    public void replyReceived(RequestContext requestContext, TOMMessage tomMessage) {

        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(tomMessage.getContent());
            ObjectInput objIn = new ObjectInputStream(byteIn);
            if (!objIn.readBoolean()) {
                //logger.info("BAD REQUEST. Proposed transaction: ({}, {}, {})", transaction.getOrigin(), transaction.getDestination(), transaction.getAmount());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else {
                System.out.println("Hello");
                //logger.info("OK. {} transferred {} coins to {}.", transaction.getOrigin(), transaction.getAmount(), transaction.getDestination());
                blockingQueue.put(1);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ResponseStatusException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }


    }
}
