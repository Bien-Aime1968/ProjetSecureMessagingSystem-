import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class ebata {

    public static void main(String[] args) throws Exception {
        // Génération des clés pour deux utilisateurs
        KeyPair bienaimeKeyPair = generateKeyPair();
        KeyPair tdsiKeyPair = generateKeyPair();

        // Sauvegarde des clés dans des fichiers
        saveKeyToFile("bienaime_public.key", bienaimeKeyPair.getPublic());
        saveKeyToFile("bienaime_private.key", bienaimeKeyPair.getPrivate());
        saveKeyToFile("tdsi_public.key", tdsiKeyPair.getPublic());
        saveKeyToFile("tdsi_private.key", tdsiKeyPair.getPrivate());

        // Échange de clés
        PublicKey bienaimePublicKey = readPublicKeyFromFile("bienaime_public.key");
        PublicKey tdsiPublicKey = readPublicKeyFromFile("tdsi_public.key");

        // Chiffrement et déchiffrement
        String message = "Bonjour, je suis EBATA et ceci est mon examen du deuxieme semestre !";
        byte[] encryptedMessage = encryptMessage(message, tdsiPublicKey);
        String decryptedMessage = decryptMessage(encryptedMessage, tdsiKeyPair.getPrivate());
        System.out.println("Message déchiffré: " + decryptedMessage);

        // Signature numérique
        byte[] signature = signMessage(message, bienaimeKeyPair.getPrivate());
        boolean verified = verifySignature(message, signature, bienaimePublicKey);
        System.out.println("Signature vérifiée: " + verified);

        // Hashing (Message Digest)
        byte[] hashedMessage = hashMessage(message);
        System.out.println("Hash du message: " + Base64.getEncoder().encodeToString(hashedMessage));

        // Code d'authentification de Message (MAC)
        byte[] mac = generateMAC(message, bienaimeKeyPair.getPrivate());
        boolean macVerified = verifyMAC(message, mac, bienaimeKeyPair.getPublic());
        System.out.println("MAC vérifié: " + macVerified);
    }

    // Génération de la paire de clés
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    // Sauvegarde de la clé dans un fichier
    public static void saveKeyToFile(String examen, Key key) throws Exception {
        byte[] keyBytes = key.getEncoded();
        Files.write(Paths.get(examen), keyBytes);
    }

    // Lecture de la clé publique depuis un fichier
    public static PublicKey readPublicKeyFromFile(String examen) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(examen));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    // Chiffrement du message
    public static byte[] encryptMessage(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    // Déchiffrement du message
    public static String decryptMessage(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    // Signature numérique du message
    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    // Vérification de la signature numérique
    public static boolean verifySignature(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes());
        return sig.verify(signature);
    }

    // Hashing (Message Digest)
    public static byte[] hashMessage(String message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(message.getBytes());
    }

    // Génération du code d'authentification de message (MAC)
    public static byte[] generateMAC(String message, PrivateKey privateKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(privateKey.getEncoded(), "HmacSHA256"));
        return mac.doFinal(message.getBytes());
    }

    // Vérification du code d'authentification de message (MAC)
    public static boolean verifyMAC(String message, byte[] mac, PublicKey publicKey) throws Exception {
        Mac verifyMac = Mac.getInstance("HmacSHA256");
        verifyMac.init(new SecretKeySpec(publicKey.getEncoded(), "HmacSHA256"));
        byte[] generatedMac = verifyMac.doFinal(message.getBytes());
        return Arrays.equals(generatedMac, mac);
    }
}
