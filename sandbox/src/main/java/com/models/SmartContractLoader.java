package com.models;

import com.google.gson.Gson;

import java.lang.reflect.InvocationTargetException;

public class SmartContractLoader extends ClassLoader {

    private final byte[] bytecode;
    private Class<ISmartContract> clasS;

    public SmartContractLoader(byte[] bytecode) {
        super(ClassLoader.getSystemClassLoader());
        this.bytecode = bytecode;
        this.clasS = null;
    }

    public ISmartContract getNewSmartContractInstance(String author, String date) throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        return clasS.getDeclaredConstructor(String.class, String.class).newInstance(author, date);
    }

    public boolean loadSmartContract() {
        try {
            this.clasS = validateClass(defineClass(null, bytecode, 0, bytecode.length));
            return true;
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            return false;
        }
    }


    private Class<ISmartContract> validateClass(Class<?> scClass) throws ClassNotFoundException {
        return (Class<ISmartContract>) super.loadClass(scClass.getName());
    }
}
