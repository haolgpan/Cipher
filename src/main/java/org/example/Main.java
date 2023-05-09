package org.example;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;

import static org.example.UtilitatsXifrar.getPublicKey;

public class Main {
    public static void main(String[] args) {
        UtilitatsXifrar ux = new UtilitatsXifrar();
        Scanner sc = new Scanner(System.in);
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

        //A5 Act 1.1----------------------------------------------------------------------------------------------------
        //Genera un parell de claus (KeyPair) de 1024bits, i utilitza-les per xifrar i desxifrar
        //un missatge.
        try {
            // Generar parell de claus de 1024 bits
            KeyPair keys = ux.randomGenerate(1024);
            PublicKey pubKey = keys.getPublic();
            PrivateKey privKey = keys.getPrivate();
            //Act 1.3
            System.out.println("Solució per act 1.iii------------------------------------------------------------");
            System.out.println(pubKey.getAlgorithm() + "\n" +
            privKey.getAlgorithm() + "\n" +
            pubKey.getFormat() + "\n" +
            privKey.getFormat() + "\n" +
            pubKey.getClass() + "\n" +
            privKey.getClass() + "\n" +
                    pubKey + "\n" +
                    privKey);


            // Missatge a xifrar
            System.out.println("Solució per act 1.i i 1.ii------------------------------------------------------");
            System.out.println("Introdueix text a xifrar:");
            //Act 1.2
            text = sc.nextLine();

            // Xifrar el missatge amb la clau pública
            encryptedData = ux.encryptDataPublic(pubKey, text.getBytes());

            // Desxifrar el missatge amb la clau privada
            decryptedData = ux.decryptDataPrivate(privKey, encryptedData);
            decryptedText = new String(decryptedData);


            // Mostrar resultats
            System.out.println("Missatge original: " + text);
            System.out.println("Missatge xifrat: " + new String(encryptedData));
            System.out.println("Missatge desxifrat: " + decryptedText);
        } catch (Exception ex) {
            System.err.println("Error: " + ex);
        }

        //A5 Act 2 -----------------------------------------------------------------------------------------------------
        String alias = "";
        String keystorePwd = "cocopower";
        KeyStore ks = null;
        try {
            System.out.println("Solució Act2------------------------------------------------------------------------");

            ks = ux.loadKeyStore("keystore_nickname.ks", keystorePwd);

            // 1. Tipus de keystore
            System.out.println("Keystore Type: " + ks.getType());

            // 2. Mida del magatzem
            System.out.println("Keystore Size: " + ks.size());

            // 3. Àlies de totes les claus emmagatzemades
            Enumeration<String> aliases = ks.aliases();
            System.out.println("Keystore Aliases: ");
            while (aliases.hasMoreElements()) {
                alias = aliases.nextElement();
                System.out.println(alias);
            }

            // 4. El certificat d’una de les claus
            Certificate cert = ks.getCertificate("mykey2");
            System.out.println("Certificate for alias " + "mykey2" + ": ");
            System.out.println(cert.toString());

            // 5. L'algorisme de xifrat d’alguna de les claus
            Key key = ks.getKey("mykey2", keystorePwd.toCharArray());
            String algorithm = key.getAlgorithm();
            System.out.println("Key Algorithm for alias " + "mykey2" + ": " + algorithm);

        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("Solucio 2.ii----------------------------------------------------------------------------");
        // Genera una nova clau simètrica
        keySize = 128;
        SecretKey sKeyA5 = ux.keygenKeyGeneration(keySize);

        // Store the key in the keystore
       String newAlias = "haoKey";
        try {
            ks = ux.loadKeyStore("keystore_nickname.ks", keystorePwd);
            KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(sKeyA5);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keystorePwd.toCharArray());
            ks.setEntry(newAlias, entry, protParam);
            // Save the keystore to a file
            FileOutputStream out = new FileOutputStream("keystore_nickname.ks");
            ks.store(out, keystorePwd.toCharArray());
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        //A5 Act 3 -----------------------------------------------------------------------------------------------------
        try {
            System.out.println("Solució Act3-------------------------------------------------------------------------");
            PublicKey publicKey = getPublicKey("mycert.cer");
            System.out.println("Dades del certificat mycert.cer:");
            System.out.println(publicKey.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }

        //A5 Act 4 -----------------------------------------------------------------------------------------------------
        PublicKey publicKey = null;
        try {
            System.out.println("Solució Act4-------------------------------------------------------------------------");
            ks = ux.loadKeyStore("keystore_nickname.ks", "cocopower");
            Key key = ks.getKey("mykey2", keystorePwd.toCharArray());
            System.out.println(key.getClass().getName());
            publicKey = getPublicKey(ks, "mykey2", "cocopower");
            System.out.println(publicKey.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }

        //A5 Act 5 -----------------------------------------------------------------------------------------------------
        byte[] data = null;
        byte[] signature = null;
        Path path = Paths.get("dades.txt");
        System.out.println("Solució Act5-------------------------------------------------------------------------");
        try {
            // llegir la PrivateKey del keystore
            ks = ux.loadKeyStore("keystore_nickname.ks", "cocopower");
            PrivateKey privateKey = ux.getPrivateKey(ks, "mykey2", "cocopower");

            // llegir les dades a signar
            data = Files.readAllBytes(path);

            // signar les dades amb la PrivateKey
            signature = ux.signData(data, privateKey);

            // imprimir la signatura
            System.out.println("Signatura: " + new String(signature));
        } catch (Exception e) {
            e.printStackTrace();
        }

        //A5 Act 6 -----------------------------------------------------------------------------------------------------
        boolean isValid = ux.validateSignature(data, signature, publicKey);
        System.out.println("Solució Act6-------------------------------------------------------------------------");
        if (isValid) {
            System.out.println("La signatura és vàlida.");
        } else {
            System.out.println("La signatura no és vàlida.");
        }

        try {
            ks = ux.loadKeyStore("keystore_nickname.ks", "cocopower");
            publicKey = getPublicKey(ks, "lamevaclaum9", "cocopower");
            isValid = ux.validateSignature(data, signature, publicKey);
            if (isValid) {
                System.out.println("La signatura és vàlida.");
            } else {
                System.out.println("La signatura no és vàlida.");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        PrivateKey privateKey = null;
        byte[][] dadesEmbolcallades = null;
        byte[] dadesDesembolcat = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            data = Files.readAllBytes(path);
            dadesEmbolcallades = ux.encryptWrappedData(data,publicKey);
            System.out.println("Text xifrat embolcallat: " + new String(dadesEmbolcallades[0]));
            dadesDesembolcat = ux.decryptWrappedData(dadesEmbolcallades,privateKey);
            System.out.println("Text desxifrat embolcallat: " + new String(dadesDesembolcat));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}