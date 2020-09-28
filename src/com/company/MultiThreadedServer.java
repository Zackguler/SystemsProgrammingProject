import javax.crypto.Cipher;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class MultiThreadedServer {
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_RESET = "\u001B[0m";

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(6789);
        // STEP 1. Generate the Keys. Read them from a file.
        byte[] keyBytes = Files.readAllBytes(new File("KeyStore/privateKey").toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);

        keyBytes = Files.readAllBytes(new File("KeyStore/publicKey").toPath());
        X509EncodedKeySpec spec2 = new X509EncodedKeySpec(keyBytes);
        PublicKey publicKey = kf.generatePublic(spec2);

        System.out.println("SERVER IS UP");
        while (true) {
            Socket connectionSocket = serverSocket.accept();

            ObjectInputStream inFromClient = new ObjectInputStream(connectionSocket.getInputStream());
            ObjectOutputStream outToClient = new ObjectOutputStream(connectionSocket.getOutputStream());
            byte[] plain_text;
            byte[] encrypted_text;
            byte[] decrypted_text;
            Cipher cipher;

            cipher = Cipher.getInstance("RSA");

            String msgBase64 = (String) inFromClient.readObject();
            System.out.println("Base64 Encoded encrypted_text come from client :" + msgBase64);
            encrypted_text = Base64.getDecoder().decode(msgBase64);

            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            decrypted_text = cipher.doFinal(encrypted_text);

            String something = new String(decrypted_text);

            System.out.println("Something is " + something);
            String changedSomething = colorChanger(shift(something.toLowerCase()));
            System.out.println("Changed is " + changedSomething);

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            plain_text = changedSomething.getBytes("UTF-8");

            encrypted_text = cipher.doFinal(plain_text);
            String resultMsgBase64 = Base64.getEncoder().encodeToString(encrypted_text);
            System.out.println("Base64 Encoded encrypted_text send to client :" + resultMsgBase64);

            outToClient.writeObject(resultMsgBase64);

        }
    }

    public static String shift(String letter) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < letter.length(); i++) {
            char c = letter.charAt(i);
            c = (char) (c + 3);
            result.append(c);
        }

        return result.toString();
    }

    public static String colorChanger(String letter) {
        return ANSI_RED + letter + ANSI_RESET;
    }


}
