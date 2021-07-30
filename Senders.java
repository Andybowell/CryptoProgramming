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
private static String fileName;

public static void main(String[] args) throws Exception {
foo();
AESEncryption();
RSAEncryption();

}

public static void foo() throws Exception {

// Read the Kxy from symmetric.key
System.out.println("");
FileInputStream fileStream = new FileInputStream("symmetric.key");
ObjectInputStream objStream = new ObjectInputStream(fileStream);

Object Kxy = objStream.readObject();

System.out.print("Kxy = ");
System.out.println(Kxy);
objStream.close();
System.out.println("");
// Read M from input file
Scanner scan = new Scanner(System.in);
System.out.print("Input the name of the message file: ");
fileName = scan.nextLine();
scan = new Scanner(new File(fileName));

String text = "";
while (scan.hasNextLine()) {
text += scan.nextLine() + "\n";
System.out.println("M: \n" + text);
}
// System.out.println(text);
// scan.close();

// fileStream = new FileInputStream(fileName);
// objStream = new ObjectInputStream(fileStream);

// String M = objStream.read();
// System.out.print("M = ");
// System.out.println(M);
// objStream.close();

// Append Kxy + M + Kxy

FileOutputStream file = new FileOutputStream("message.kmk");
ObjectOutputStream output = new ObjectOutputStream(file);
output.writeObject(Kxy + "\n");
output.writeObject(text);
output.writeObject(Kxy);
output.close();

/*
* Calculate the keyed hash MAC, i.e., the SHA256 hash value of (Kxy || M ||Kxy), SAVE this keyed hash MAC *into a file named “message.khmac”, and DISPLAY
* it in Hexadecimal bytes.
*/
String hash = md("message.kmk");

System.out.println("message.kmk: " + hash);

}

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

System.out.println("digit digest (hash value):");
for (int k = 0, j = 0; k < hash.length; k++, j++) {
System.out.format("%2X ", new Byte(hash[k]));
if (j >= 15) {
System.out.println("");
j = -1;
}
}
System.out.println("");

/*
* o An added feature for testing whether the receiver’s program can handle the
* case properly when the keyed hash MAC calculated in Step 6 (the receiver’s
* program) is different from the keyed hash MAC in the “message.khmac” file:
* After calculating SHA256(Kxy || M || Kxy) but before saving it to the file
* named “message.khmac” (the sender’s program), display a prompt “ Do you want
* to invert the 1st byte in SHA256(Kxy||M||Kxy)? (Y or N) ”, o If the user
* input is ‘Y’, modify the first byte in your byte array holding SHA256(Kxy ||
* M || Kxy) by replacing it with its bitwise inverted value (hint: the ~
* operator in Java does it), complete the rest of Step 5 by SAVING & DISPLAYING
* the modified SHA256(Kxy || M || Kxy), instead of the original SHA256(Kxy || M
* || Kxy), and
*/

Scanner scan = new Scanner(System.in);
System.out.println("Do you want to invert the 1st byte in SHA256(Kxy||M||Kxy)? (Y or N)");
char choice = scan.next().charAt(0);

if (choice == 'Y')
hash[0] = (byte) ~hash[0];

// Read Kxy || M || Kxy piece by piece from the file “message.kmk”, where each
// piece is recommended to be
// a small multiple of 1024 bytes, calculate the keyed hash MAC, i.e., the
// SHA256 hash value of
// (Kxy || M || Kxy), SAVE this keyed hash MAC into a file named
// “message.khmac”, and DISPLAY it in
// Hexadecimal bytes

// SAVE this keyed hash MAC into a file named “message.khmac”, and DISPLAY it in
// Hexadecimal bytes.
// FileOutputStream OutFile = new FileOutputStream("message.khmac");
// ObjectOutputStream output = new ObjectOutputStream(OutFile);

// for (int k = 0, j = 0; k < hash.length; k++, j++) {
// output.write(new Byte(hash[k]));
// }
// output.close();


FileOutputStream OutFile = new FileOutputStream("message.khmac");
OutFile.write(hash);


// Read message.khmac just to verify
// FileInputStream fileStream = new FileInputStream("message.khmac");
// System.out.println("Reading from message.khmac file");
// for (int k = 0, j = 0; k < hash.length; k++, j++) {
// System.out.format("%2X ", new Byte(objStream.readByte()));
// if (j >= 15) {
// System.out.println("");
// j = -1;
// }
// }
// System.out.println("");

// objStream.close();
return new String(hash);

}

public static void AESEncryption() throws Exception {
// read M
// Read M from input file
// Scanner scan = new Scanner(System.in);
// System.out.print("Input the name of the message file: ");
//String fileName = scan.nextLine();

Scanner scan = new Scanner(new File(fileName));

String text = "";
while (scan.hasNextLine()) {
text += scan.nextLine() + "\n";
System.out.println("M: \n " + text);
}

// Read Kxy
FileInputStream fileStream = new FileInputStream("symmetric.key");
ObjectInputStream objStream = new ObjectInputStream(fileStream);

Object Kxy = objStream.readObject();

// System.out.print("Kxy = ");
// System.out.println(Kxy);
objStream.close();

byte[] M = encrypt(text, (String) Kxy);
//Display what the ciphertext looks like
System.out.println("CipherText: ");
for (int k = 0, j = 0; k < M.length; k++, j++) {
System.out.format("%2X ", new Byte(M[k]));
if (j >= 15) {
System.out.println("");
j = -1;
}
}
System.out.println("");

// //Write the encrypted array to message.aescipher
// FileOutputStream OutFile = new FileOutputStream("message.aescipher");
// ObjectOutputStream output = new ObjectOutputStream(OutFile);

// for (int k = 0; k < M.length; k++) {
// output.write(M[k]);
// }
// output.close();
// System.out.println("\n");


FileOutputStream OutFile = new FileOutputStream("message.aescipher");
OutFile.write(M);
System.out.println("\n");

//checking if the padding can be removed for decryption.
// System.out.println("\n\n");
// System.out.println("Decrpyted Output:");
// System.out.println(Decrypt(M, (String)Kxy));
}

public static byte[] encrypt(String plaintext, String encryptionKey) throws Exception {
String IV = "AAAAAAAAAAAAAAAA";
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
//Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
// Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
// Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
return cipher.doFinal(plaintext.getBytes("UTF-8"));
}

// Calculate the RSA Encryption of Kxy using Ky+. (Hint: if
// "RSA/ECB/PKCS1Padding" is used, what is the length of the resulting
// ciphertext?) SAVE the resulting RSA ciphertext into a file named
// “kxy.rsacipher”.

public static void RSAEncryption() throws Exception {

FileInputStream fileStream = new FileInputStream("symmetric.key");
ObjectInputStream objStream = new ObjectInputStream(fileStream);

String Kxy = (String)(objStream.readObject());

System.out.println("\n");
//printing Kxy just to check
// System.out.println("kxy = " + Kxy);

System.out.println("\n");

// Read receiver public key 
FileInputStream fileStream1 = new FileInputStream("YPublic.key");
ObjectInputStream objStream1 = new ObjectInputStream(fileStream1);

Object Kyp = objStream1.readObject();

//Printing out the receiver public key
// System.out.print("Receiver Public Key = ");
// System.out.println(Kyp);
// objStream.close();
// System.out.println("\n");

Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

cipher.init(Cipher.ENCRYPT_MODE, (Key) Kyp);

// byte[] rsacipher = cipher.doFinal( ((Key)Kxy).toByteArray());

byte[] rsacipher = cipher.doFinal(Kxy.getBytes());
System.out.println("rsacipher: ");
for (int i = 0, j = 0; i < rsacipher.length; i++, j++) {
System.out.format("%2X ", new Byte(rsacipher[i]));
if (j >= 15) {
System.out.println("");
j = -1;
}

}

// byte[] rsacipher = encrypt((String)Kxy, (String) Kyp);

// System.out.println(Arrays.toString(rsacipher));

// Write the encypted array to Kxy.rsacipher
// FileOutputStream OutFile = new FileOutputStream("Kxy.rsacipher");
// ObjectOutputStream output = new ObjectOutputStream(OutFile);

// for (int t = 0; t < rsacipher.length; t++) {
// output.write(rsacipher[t]);
// }

// output.close();

FileOutputStream OutFile = new FileOutputStream("Kxy.rsacipher");
OutFile.write(rsacipher);

}

}

