package org.example;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

public class UtilitatsXifrar {

    //ACT1--------------------------------------------------------------------------------------------------------------
    public SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    //ACT2--------------------------------------------------------------------------------------------------------------
    public SecretKey passwordKeyGeneration(String text, int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize / 8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }

    //ACT3--------------------------------------------------------------------------------------------------------------
    public byte[] encryptData(SecretKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    //ACT4--------------------------------------------------------------------------------------------------------------
    public byte[] decryptData(SecretKey sKey, byte[] encryptedData) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData = cipher.doFinal(encryptedData);
        } catch (BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            System.out.println("Error desxifrant les dades: " + ex);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return decryptedData;
    }

    //A5 Act1-----------------------------------------------------------------------------------------------------------
    //Afegeix a la classe d’utilitats de criptografia de l’activitat A4 el mètode 1.2.1
    //randomGenerate del apunts.
    public KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public byte[] encryptDataPublic(PublicKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
            ex.printStackTrace();
        }
        return encryptedData;
    }

    public byte[] decryptDataPrivate(PrivateKey sKey, byte[] encryptedData) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData = cipher.doFinal(encryptedData);
        } catch (BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            System.out.println("Error desxifrant les dades: " + ex);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        return decryptedData;
    }

    //A5 Act 2----------------------------------------------------------------------------------------------------------
    public KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    //A5 Act 3 ---------------------------------------------------------------------------------------------------------
    public static PublicKey getPublicKey(String fitxer) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(fitxer);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        return cert.getPublicKey();
    }

    public static PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws Exception {
        Key key = ks.getKey(alias, pwMyKey.toCharArray());
        if (key == null) {
            throw new Exception("No s'ha trobat la clau amb àlies " + alias);
        }
        if (!(key instanceof RSAPrivateCrtKey)) {
            throw new Exception("La clau amb àlies " + alias + " no és una clau RSA privada");
        }
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key;
        RSAPublicKeySpec spec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    public static PrivateKey getPrivateKey(KeyStore ks, String alias, String pwMyKey) {
        Key key = null;
        try {
            key = ks.getKey(alias, pwMyKey.toCharArray());
            if (key == null) {
                throw new Exception("No s'ha trobat la clau amb àlies " + alias);
            }
            if (!(key instanceof PrivateKey)) {
                throw new Exception("La clau amb àlies " + alias + " no és una clau privada");
            }


        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (PrivateKey) key;
    }

    //Generació de firma digital RSA
    public byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;

        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    //Validació de firma digital RSA
    public boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

    //A5 Act Clau embolcallada------------------------------------------------------------------------------------------
    public byte[][] encryptWrappedData(byte[] data, PublicKey pub) { // Dades i clau pública del receptor
        byte[][] encWrappedData = new byte[2][];
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey(); // Genera clau simètrica
            Cipher cipher = Cipher.getInstance("AES"); // Algorisme de xifrat simètric amb AES
            cipher.init(Cipher.ENCRYPT_MODE, sKey); // Configura amb la clau simètrica sKey
            byte[] encMsg = cipher.doFinal(data); // Encriptació de les dades simmètricament
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Algorisme de xifrat asimètric
            cipher.init(Cipher.WRAP_MODE, pub); // Configura amb la clau pública del receptor
            byte[] encKey = cipher.wrap(sKey); // Clau simètrica xifrada
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData; //Dades embolcallades.
    }

    public byte[] decryptWrappedData(byte[][] encWrappedData, PrivateKey priv) { //Dades xifrades amb clau xifrada i clau privada del receptor
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Algorisme de xifrat asimètric
            cipher.init(Cipher.UNWRAP_MODE, priv); // Clau privada del receptor
            Key key = cipher.unwrap(encWrappedData[1], "AES", Cipher.SECRET_KEY); // Algorisme de xifrat simètric on extreu la clau simètrica amb la clau privada del receptor
            cipher = Cipher.getInstance("AES"); // Configurar per desencriptar amb algorisme simètric AES
            cipher.init(Cipher.DECRYPT_MODE, key); // Configurar en mode de desencriptació amb la clau simètrica
            decryptedData = cipher.doFinal(encWrappedData[0]); // Dades desencriptades
        } catch (Exception ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
        }
        return decryptedData;
    }

}
