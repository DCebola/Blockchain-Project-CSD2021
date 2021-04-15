package main.java.bftsmart.app.counter;

import java.io.Serializable;

public class Test implements Serializable {

    private int a,b;

    public Test(int a, int b) {
        this.a = a;
        this.b = b;
    }

    public int getA() {
        return a;
    }

    public int getB() {
        return b;
    }
}
