package csd.wa1.controllers;

import bftsmart.tom.ServiceProxy;
import org.springframework.boot.CommandLineRunner;
import org.springframework.web.bind.annotation.*;

import java.io.*;

@RestController
public class LedgerController implements CommandLineRunner {

    private ServiceProxy serviceProxy;

    @PostMapping("/{who}/obtainCoins")
    public double obtainAmount(@PathVariable String who, @RequestBody double amount) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.OBTAIN_COINS);
            objOut.writeObject(who);
            objOut.writeDouble(amount);
            objOut.flush();
            byteOut.flush();
            byte[] reply = serviceProxy.invokeOrdered(byteOut.toByteArray());
            ByteArrayInputStream byteIn = new ByteArrayInputStream(reply);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            return objIn.readDouble();

        } catch (IOException e) {
            e.printStackTrace();
        }

        return -2;
    }

    @Override
    public void run(String... args) {
        try {
            if (args.length == 1) {
                int id = Integer.parseInt(args[0]);
                System.out.println("Launching client " + id);
                this.serviceProxy = new ServiceProxy(id);
            } else System.out.println("Missing param: client ID");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
