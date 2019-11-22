import javax.crypto.Cipher;
import java.io.File;
import java.io.FileReader;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class UseKeys {


    public static void main(String args[]) throws Exception {
        String plainText = "My name is mohammed elamin";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
//
        PublicKey publicKey = getPublicKeyFromFile();
        PrivateKey privateKey = getPrivateKeyFromFile();
//
        byte[] cipherTextArray = encrypt(plainText, publicKey);
        String encryptedText = Base64.getEncoder().encodeToString(cipherTextArray);
        System.out.println("Encrypted Text : ----->" + encryptedText);
//
        String decryptedText = decrypt(cipherTextArray, privateKey);
        System.out.println("DeCrypted Text ------>: " + decryptedText);

    }










    public static byte[] encrypt(String plainText, Key publicKey) throws Exception {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Perform Encryption
        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        return cipherText;
    }

    public static String decrypt(byte[] cipherTextArray, Key privateKey) throws Exception {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Perform Decryption
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

        return new String(decryptedTextArray);
    }


    private static PublicKey getPublicKeyFromFile() throws Exception {
        File file = new File("public.txt");
        FileReader fileReader = new FileReader(file);
        StringBuffer stringBuffer = new StringBuffer();
        int numCharsRead;
        char[] charArray = new char[1024];
        while ((numCharsRead = fileReader.read(charArray)) > 0) {
            stringBuffer.append(charArray, 0, numCharsRead);
        }
        fileReader.close();

//
        KeyFactory kf = KeyFactory.getInstance("RSA");
        byte[] pKeyAsByte = Base64.getDecoder().decode(stringBuffer.toString());
        PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(pKeyAsByte));
        return pk;
    }

    private static PrivateKey getPrivateKeyFromFile() throws Exception {
        File file = new File("private.txt");
        FileReader fileReader = new FileReader(file);
        StringBuffer stringBuffer = new StringBuffer();
        int numCharsRead;
        char[] charArray = new char[1024];
        while ((numCharsRead = fileReader.read(charArray)) > 0) {
            stringBuffer.append(charArray, 0, numCharsRead);
        }
        fileReader.close();


        KeyFactory kf = KeyFactory.getInstance("RSA");
        byte[] prKeyAsByte = Base64.getDecoder().decode(stringBuffer.toString());
        return kf.generatePrivate(new PKCS8EncodedKeySpec(prKeyAsByte));
    }


}
