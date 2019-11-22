import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyGen {


    public static void main(String args[]) throws Exception {

        saveMyKeysIntoFile();
//        System.out.println("My public key--->" + myKeys.getPublicKey());
//        System.out.println("My private key--->" + myKeys.getPrivateKey());

    }

    public  static  void  saveMyKeysIntoFile()throws Exception{
        MyKeys myKeys=keyGeneration();

//        write in public key
        File pubFile = new File("public.txt");
        FileWriter pubFileWriter = new FileWriter(pubFile);
        pubFileWriter.write(myKeys.getPublicKey());
        pubFileWriter.flush();
        pubFileWriter.close();


        File prFile = new File("private.txt");
        FileWriter prFileWriter = new FileWriter(prFile);
        prFileWriter.write(myKeys.getPrivateKey());
        prFileWriter.flush();
        prFileWriter.close();

//        private key

    }


    public static MyKeys keyGeneration() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String publicKeyAsBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyKeyAsBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return new MyKeys(publicKeyAsBase64, privateKeyKeyAsBase64);
    }

    public static MyKeyEncoded encodeMyKeys(MyKeys myKeys) throws Exception {




        byte[] pKeyAsByte = Base64.getDecoder().decode(myKeys.getPublicKey());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        byte[] prKeyAsByte = Base64.getDecoder().decode(myKeys.getPrivateKey());
        PrivateKey prK = kf.generatePrivate(new PKCS8EncodedKeySpec(prKeyAsByte));
//        generate your public  key from string
        PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(pKeyAsByte));

        return new MyKeyEncoded(pk, prK);
    }
}

class MyKeyEncoded {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public MyKeyEncoded(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }


    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
class MyKeys {
    private String publicKey;
    private String privateKey;

    public MyKeys(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}