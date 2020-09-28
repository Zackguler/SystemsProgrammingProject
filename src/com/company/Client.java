import javax.crypto.Cipher;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;


public class Client {

    public static void main(String[] args) throws Exception {
        Socket clientSocket = new Socket("localhost", 6789);
        ObjectOutput outToServer = new ObjectOutputStream((clientSocket.getOutputStream()));
        ObjectInputStream inFromServer = new ObjectInputStream(clientSocket.getInputStream());
        Scanner scanner = new Scanner(System.in);
        byte[] plain_text;
        byte[] encrypted_text;
        byte[] decrypted_text;
        Cipher cipher;

        System.out.println("Welcome to client. Please write something.");
        String something = scanner.next();

        plain_text = something.getBytes("UTF-8");
        // STEP 1. Generate the Keys. Read them from a file.
        byte[] keyBytes = Files.readAllBytes(new File("KeyStore/privateKey").toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);

        keyBytes = Files.readAllBytes(new File("KeyStore/publicKey").toPath());
        X509EncodedKeySpec spec2 = new X509EncodedKeySpec(keyBytes);
        PublicKey publicKey = kf.generatePublic(spec2);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        encrypted_text = cipher.doFinal(plain_text);

        String msgBase64 = Base64.getEncoder().encodeToString(encrypted_text);
        System.out.println("Base64 Encoded encrypted_text send to server :" + msgBase64);

        outToServer.writeObject(msgBase64);

        String fromServerMessage = (String) inFromServer.readObject();
        System.out.println("Base64 Encoded encrypted_text come from server :" + fromServerMessage);
        encrypted_text = Base64.getDecoder().decode(fromServerMessage);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        decrypted_text = cipher.doFinal(encrypted_text);
        System.out.println(new String(decrypted_text));

        System.out.println("FINISHED JOB :)");
        clientSocket.close();
    }
}
