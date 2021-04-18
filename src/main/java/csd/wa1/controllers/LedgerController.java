package csd.wa1.controllers;
import bftsmart.tom.ServiceProxy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
public class LedgerController {

    @Value("${bftclient_id}")
    private int id;

    private ServiceProxy serviceProxy;

    @PostMapping("/{who}/obtainCoins")
    public double obtainAmount(@PathVariable String who, @RequestBody double amount) {
        if(serviceProxy == null) {
            System.out.println("hello");
            serviceProxy = new ServiceProxy(id);
        }

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

}
