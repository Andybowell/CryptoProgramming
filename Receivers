import java.io.*;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class Main {
    private static int BUFFER_SIZE = 32 * 1024;
    static String IV = "AAAAAAAAAAAAAAAA";
    public static byte[] Kxy;

    public static void main(String[] args) throws Exception {
        RSADecryption();
        AESDecryption();
        md("message.kmk");
    }

    public static void RSADecryption() throws Exception {
        // Read the information on the keys to be used in this program from the key file
        // and generate Ky– (Kym).
        FileInputStream fileStream = new FileInputStream("YPrivate.key");
        ObjectInputStream objStream = new ObjectInputStream(fileStream);

        Key Kym = (Key)(objStream.readObject());

        System.out.println("Ky- = " + Kym);

        File file = new File("Kxy.rsacipher");

        byte[] rsacipher = new byte[(int)file.length()];

        fileStream = new FileInputStream(file);
        fileStream.read(rsacipher);
        fileStream.close();

        System.out.println("\n\n");
        for (int i = 0, j = 0; i < rsacipher.length; i++, j++) {
            System.out.format("%2X ", new Byte(rsacipher[i]));
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }

        // Calculate the RSA Decryption of C1 using Ky– to get the random symmetric key
        // Kxy
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, Kym);
        Kxy = cipher.doFinal(rsacipher);
        // System.out.println("Kxy: " + new String(Kxy) + "\n");

        // DISPLAY Kxy in Hexadecimal bytes
        System.out.print("Kxy in Hexadecimal byte: ");
        for (int i = 0, j = 0; i < Kxy.length; i++, j++) {
            System.out.format("%2X ", new Byte(Kxy[i]));
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }

    }

    public static void AESDecryption() throws Exception {
        /*
         * Read the ciphertext, C2, from the file “message.aescipher” block by block,
         * where each block needs to be a multiple of 16 bytes long. (Hint: if the
         * length of the last block is less than that multiple of 16 bytes, it needs to
         * be placed in a byte array whose array size is the length of the last piece
         * before being decrypted.) Calculate the AES Decryption of C2 block by block
         * using the Kxy obtained in Step 4 to get M, WRITE the resulting pieces of M
         * into the file specified in Step 3, and also APPEND those resulting pieces of
         * M to the file “message.kmk” created in Step 4. Finally APPEND Kxy after M to
         * the file “message.kmk”. (Hint: at the end of this Step, Kxy || M || Kxy is
         * written to the file “message.kmk”, and M is written to the file specified in
         * Step 3.)
         */

        // Read the CipherText, C2, from the file “message.aescipher”
        // FileInputStream fileStream = new FileInputStream("message.aescipher");
        // ObjectInputStream objStream = new ObjectInputStream(fileStream);
        // byte[] CipherText = (byte[])(objStream.readAllBytes());


        File file_message = new File("message.aescipher");

        byte[] CipherText = new byte[(int)file_message.length()];

        FileInputStream fileStream = new FileInputStream(file_message);
        fileStream.read(CipherText);
        fileStream.close();


        System.out.println("\n\n");
        System.out.println("CipherText: ");
        for (int i = 0, j = 0; i < CipherText.length; i++, j++) {
            System.out.format("%2X ", new Byte(CipherText[i]));
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }

        String M = decrypt(CipherText, new String(Kxy));
        System.out.println("");
        /*
         * Display a prompt “Input the name of the message file:” and take a user input
         * from the keyboard. The resulting message M will be saved to this file at the
         * end of this program.
         */

        Scanner scan = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String fileName = scan.nextLine();

        FileOutputStream fout = new FileOutputStream(fileName);
        BufferedOutputStream bout = new BufferedOutputStream(fout);
        bout.write(M.getBytes());
        bout.flush();
        bout.close();
        fout.close();

        FileOutputStream file = new FileOutputStream("message.kmk");
        ObjectOutputStream output = new ObjectOutputStream(file);
        output.writeObject(new String(Kxy) + "\n");
        output.writeObject(M);
        output.writeObject(new String(Kxy));
        output.close();

        /*
         * Calculate the keyed hash MAC, i.e., the SHA256 hash value of (Kxy || M ||
         * Kxy), SAVE this keyed hash MAC into a file named “message.khmac”, and DISPLAY
         * it in Hexadecimal bytes.
         */
        //String hash = md("message.kmk");

        //System.out.println("message.kmk: " + hash);

    }

    public static String decrypt(byte[] cipherText, String encryptionKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        // Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
        // Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
        SecretKeySpec KxySpec = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.DECRYPT_MODE, KxySpec, new IvParameterSpec(IV.getBytes("UTF-8")));
        return new String(cipher.doFinal(cipherText), "UTF-8");
    }

    /*
     * Read Kxy || M || Kxy piece by piece from the file “message.kmk”, where each
     * piece is recommended to be a small multiple of 1024 bytes, calculate the
     * keyed hash MAC, i.e., the SHA256 hash value of (Kxy || M || Kxy), COMPARE
     * this keyed hash MAC with the keyed hash MAC read from the file
     * “message.khmac”, DISPLAY whether it passes the message authentication
     * checking, and DISPLAY both keyed hash MACs in Hexadecimal bytes.
     */

    // Read Kxy || M || Kxy piece by piece from the file “message.kmk”, where each
    // piece is recommended to be a small multiple of 1024 bytes

    public static String md(String f) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, md);
        int i;
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            i = in .read(buffer, 0, BUFFER_SIZE);
        } while (i == BUFFER_SIZE);
        md = in .getMessageDigest(); in .close();

        byte[] hash = md.digest();

        System.out.println("");

        System.out.println("digit digest (hash value):");
        for (int k = 0, j = 0; k < hash.length; k++, j++) {
            System.out.format("%2X ", new Byte(hash[k]));
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }
        System.out.println("");

        // //Read message.khmac just to verify
        // FileInputStream fileStream = new FileInputStream("message.khmac");
        // ObjectInputStream objStream = new ObjectInputStream(fileStream);

        // System.out.println("Reading from message.khmac file");

        // byte[] khmac_hash = objStream.readAllBytes();



        File file_message = new File("message.khmac");

        byte[] khmac_hash = new byte[(int)file_message.length()];

        FileInputStream fileStream = new FileInputStream(file_message);
        fileStream.read(khmac_hash);
        fileStream.close();


        for (int k = 0, j = 0; k < hash.length; k++, j++) {
            System.out.format("%2X ", new Byte(khmac_hash[k]));
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }
        System.out.println("");

        for (int t = 0; t < hash.length; t++) {
            if (hash[t] != khmac_hash[t]) {
                System.out.println("Doesn't match!!");
                return "No";
            }
        }
        System.out.println(" match!!");

        return "Yes";
    }
}
