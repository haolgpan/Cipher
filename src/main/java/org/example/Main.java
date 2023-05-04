package org.example;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) {
        UtilitatsXifrar ux = new UtilitatsXifrar();
        //ACT5----------------------------------------------------------------------------------------------------------
        String text = "En Jonathan té una melena que no veas.";
        int keySize = 128;
        SecretKey sKey = ux.keygenKeyGeneration(keySize);

        // Xifrar el text en clar
        byte[] encryptedData = ux.encryptData(sKey, text.getBytes());

        // Desxifrar el text xifrat
        byte[] decryptedData = ux.decryptData(sKey, encryptedData);

        // Convertir els bytes desxifrats a String
        String decryptedText = new String(decryptedData);

        // Mostrar els resultats
        System.out.println("Text en clar: " + text);
        System.out.println("Clau secreta: " + sKey.toString());
        System.out.println("Text xifrat: " + new String(encryptedData));
        System.out.println("Text desxifrat: " + decryptedText);

        //ACT6----------------------------------------------------------------------------------------------------------
        String password = "cocoPowerRangers!";
        SecretKey skey2 = ux.passwordKeyGeneration(password, 256);

        text = "Power Rangers Assamble!!! Red! Blue! Pink! Yellow! Green!";
        // Xifrar el text en clar
        encryptedData = ux.encryptData(skey2, text.getBytes());

        // Desxifrar el text xifrat
        decryptedData = ux.decryptData(skey2, encryptedData);

        // Convertir els bytes desxifrats a String
        decryptedText = new String(decryptedData);

        // Mostrar els resultats
        System.out.println("Text en clar: " + text);
        System.out.println("Clau secreta: " + skey2.toString());
        System.out.println("Text xifrat: " + new String(encryptedData));
        System.out.println("Text desxifrat: " + decryptedText);

        //ACT7----------------------------------------------------------------------------------------------------------
        System.out.println(sKey.getAlgorithm());
        System.out.println(skey2.getFormat());
        System.out.println(sKey.getClass());
        System.out.println(sKey.getFormat());
        System.out.println(skey2.getAlgorithm());

        //ACT8----------------------------------------------------------------------------------------------------------
        SecretKey skey3 = ux.passwordKeyGeneration("cocoPowerRangers!", 256);
        SecretKey skey4 = ux.passwordKeyGeneration("BlackRanger", 256);

        text = "Power Rangers Assamble!!! Red! Blue! Pink! Yellow! Green!";
        // Xifrar el text en clar
        encryptedData = ux.encryptData(skey3, text.getBytes());

        // Desxifrar el text xifrat
        decryptedData = ux.decryptData(skey4, encryptedData);

        // Convertir els bytes desxifrats a String
        try {
            if (decryptedText != null) {
                decryptedText = new String(decryptedData);
                System.out.println(decryptedText);
            }
        }catch (NullPointerException e) {
//            System.out.println("Error");
        }

        //ACT Final
//        Donat un text xifrat (textamagat) amb algoritme estàndard AES i clau simètrica generada amb el
//        mètode SHA-256 a partir d’una contrasenya, i donat un fitxer (clausA4.txt) on hi ha possibles
//        contrasenyes correctes, fes un programa per trobar la bona i desxifrar el missatge.

        SecretKey sK = null;
        try {
            FileReader fr = new FileReader("clausA4.txt");
            BufferedReader br = new BufferedReader(fr);
            Path path = Paths.get("textamagat.crypt");
            byte[] textenbytes = Files.readAllBytes(path);
            String line = br.readLine();
            while (line != null){
                for (int keysize : new int[] {128, 192, 256}) {
                    System.out.println("Probant clau (" + keysize + " bits): " + line);
                    sK = ux.passwordKeyGeneration(line, keysize);
                    decryptedData = ux.decryptData(sK, textenbytes);
                    try {
                        decryptedText = new String(decryptedData);
                        System.out.println("Text desxifrat: " + decryptedText);
                        break; // sortim del bucle si la clau és correcta
                    } catch (NullPointerException e) {
                        System.out.println("Clau incorrecta");
                    }
                }
                line = br.readLine();
            }
            br.close();
            fr.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if (sK == null) {
            System.out.println("No s'ha pogut trobar la clau correcta");
        }

    }
}