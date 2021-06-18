package com.models;

import com.google.gson.Gson;

import java.lang.reflect.InvocationTargetException;

public class SmartContractLoader extends ClassLoader {

    private final byte[] bytecode;
    private final String name;
    private Class<ISmartContract> clasS;

    public SmartContractLoader(byte[] bytecode, String name) {
        super(ClassLoader.getSystemClassLoader());
        this.bytecode = bytecode;
        this.name = name;
        this.clasS = null;
    }

    public ISmartContract getNewSmartContractInstance(String author, String date, Gson gson) throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        return clasS.getDeclaredConstructor(String.class, String.class, Gson.class).newInstance(author, date, gson);
    }

    public boolean loadSmartContract() {
        try {
            this.clasS = validateClass(defineClass(name, bytecode, 0, bytecode.length));
            return true;
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            return false;
        }
    }


    private Class<ISmartContract> validateClass(Class<?> scClass) throws ClassNotFoundException {
        if (scClass.isInstance(ISmartContract.class) && !scClass.isInterface() &&
                scClass.getDeclaredClasses().length == SmartContractTemplate.class.getDeclaredClasses().length &&
                scClass.getDeclaredFields().length == SmartContractTemplate.class.getDeclaredFields().length &&
                scClass.getDeclaredMethods().length == SmartContractTemplate.class.getDeclaredMethods().length)

            return (Class<ISmartContract>) super.loadClass(name);
        throw new ClassNotFoundException();
    }
}
