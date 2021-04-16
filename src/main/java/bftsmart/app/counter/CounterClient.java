/**
Copyright (c) 2007-2013 Alysson Bessani, Eduardo Alchieri, Paulo Sousa, and the authors indicated in the @author tags

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main.java.bftsmart.app.counter;

import java.io.IOException;
import java.security.Security;

import main.java.bftsmart.app.map.MapClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Example client that updates a BFT replicated service (a counter).
 * 
 * @author alysson
 */
public class CounterClient {

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.out.println("Usage: java ... CounterClient <process id> <increment> [<number of operations>]");
            System.out.println("       if <increment> equals 0 the request will be read-only");
            System.out.println("       default <number of operations> equals 1000");
            System.exit(-1);
        }
        Security.addProvider(new BouncyCastleProvider()); //Added bouncy castle provider
        MapClient<String,Test> mapClient = new MapClient<String,Test>(Integer.parseInt(args[0]));

        int inc = Integer.parseInt(args[1]);
        int numberOfOps = (args.length > 2) ? Integer.parseInt(args[2]) : 1000;


        Test t = mapClient.put("test".concat(Integer.toString(1)),new Test(1,2));
        for(int i = 0; i < numberOfOps; i++) {
            t = mapClient.put("test".concat(Integer.toString(1)),new Test(i,2));
            //t = mapClient.put("test".concat(Integer.toString(1)),new Test(1,2));
            System.out.println("Test: "+ t.getA() + " " + t.getB());
        }




        /*ServiceProxy counterProxy = new ServiceProxy(Integer.parseInt(args[0]));

        
        try {

            int inc = Integer.parseInt(args[1]);
            int numberOfOps = (args.length > 2) ? Integer.parseInt(args[2]) : 1000;

            for (int i = 0; i < numberOfOps; i++) {

                ByteArrayOutputStream out = new ByteArrayOutputStream(4);
                //new DataOutputStream(out).writeInt(inc);

                System.out.print("Invocation " + i);
                byte[] reply = (inc == 0)?
                        counterProxy.invokeUnordered(out.toByteArray()):
                	counterProxy.invokeOrdered(out.toByteArray()); //magic happens here

                if(reply != null) {
                    int newValue = new DataInputStream(new ByteArrayInputStream(reply)).readInt();
                    System.out.println(", returned value: " + newValue);
                } else {
                    System.out.println(", ERROR! Exiting.");
                    break;
                }
            }
        } catch(IOException | NumberFormatException e){
            counterProxy.close();
        }*/
    }
}
