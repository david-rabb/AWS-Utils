package drx.aws.crypto;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
/**
 * Simplified interface for AES encryption/decryption. This implementation enforces 
 * the following specs:
 * <br>  <b>Algorithm: AES 256</b> - Symmetric Encryption with 256 bit keys
 * <br>  <b>Scheme:	GCM </b> - Authenticated Encryption with AAD, 128bit GCM tab bit length
 * <br>  <b>IV Size:	16 bytes </b>
 * <br>  <b>Text Encoding:	UTF-8 </b>
 * @author David Rabb
 */
public class AES {
  public static final String CIPHER_ALGORITHM = "AES";
  public static final String CIPHER_SCHEME = "AES/GCM/NoPadding";
  public static final String TEXT_ENCODING = "UTF-8";
  public static final int IV_SIZE = 16;
  public static final int GCM_TAG_BITLENGTH = 128;
  
  /* Convenience method to encrypt using key in base64 format. */
  public static final String encrypt(String plainText, String base64Key) {
    byte[] keyBytes = Base64.decodeBase64(base64Key);
    return encrypt(plainText, keyBytes);
  }
  
  /* AES/GCM encrypt text and return a text-based payload (EncryptionSet) containing the 
   * cipher scheme | text encoding | base64-encoded initialization vector | base64-encoded encrypted data
   * Not expected to be used with binary data.
  */
  public static final String encrypt(String plainText, byte[] keyBytes) {
    try {
      SecretKeySpec secretKey = new SecretKeySpec(keyBytes, CIPHER_ALGORITHM);
      SecureRandom random = new SecureRandom();
      byte[] iv = new byte[IV_SIZE];
      random.nextBytes(iv);
      Cipher cipher = Cipher.getInstance(CIPHER_SCHEME);
      GCMParameterSpec params = new GCMParameterSpec(GCM_TAG_BITLENGTH, iv);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
      byte[] encryptedData = cipher.doFinal(plainText.getBytes(TEXT_ENCODING));
      String result = CIPHER_SCHEME+"|"+TEXT_ENCODING+"|"+Base64.encodeBase64URLSafeString(iv)+"|"+Base64.encodeBase64URLSafeString(encryptedData);
      return result;
      
    } catch(GeneralSecurityException | UnsupportedEncodingException  e) {
      throw new RuntimeException(e);
    }
  }
  
  /* AES 256 GSM encrypt an inputstream to an outputstream. This method closes 
   * both streams at the end. 
   */
  public static final void encrypt(InputStream in, OutputStream out, byte[] keyBytes) throws IOException {
    CipherOutputStream cout = null;
    try {
      SecretKeySpec secretKey = new SecretKeySpec(keyBytes, CIPHER_ALGORITHM);
      SecureRandom random = new SecureRandom();
      byte[] iv = new byte[IV_SIZE];
      random.nextBytes(iv);
      Cipher cipher = Cipher.getInstance(CIPHER_SCHEME);
      GCMParameterSpec params = new GCMParameterSpec(GCM_TAG_BITLENGTH, iv);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
      out.write(iv);
      
      cout = new CipherOutputStream(out, cipher);
      byte[] bin = new byte[2048];
      int numread = in.read(bin);
      while (numread >-1) {
        cout.write(bin, 0, numread);
        numread = in.read(bin);
      }
    } catch(GeneralSecurityException | IOException  e) {
      throw new RuntimeException(e);
    } finally {
      if (in!=null) in.close();
      if (cout!=null) cout.close();
    }
  }
  
  /* AES 256 GSM decrypt an encrypted inputstream to a plaintext outputstream. 
  * This method closes both streams at the end. */
  public static final void decrypt(InputStream in, OutputStream out, byte[] keyBytes) throws IOException {
    CipherInputStream cin = null;
    try {
      SecretKeySpec secretKey = new SecretKeySpec(keyBytes, CIPHER_ALGORITHM);
      SecureRandom random = new SecureRandom();
      byte[] iv = new byte[IV_SIZE];
      in.read(iv);
      Cipher cipher = Cipher.getInstance(CIPHER_SCHEME);
      GCMParameterSpec params = new GCMParameterSpec(GCM_TAG_BITLENGTH, iv);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
      
      cin = new CipherInputStream(in, cipher);
      byte[] bin = new byte[2048];
      int numread = cin.read(bin);
      while (numread >-1) {
        out.write(bin, 0, numread);
        numread = cin.read(bin);
      }
    } catch(GeneralSecurityException | IOException  e) {
      throw new RuntimeException(e);
    } finally {
      if (cin!=null) cin.close();
      if (out!=null) out.close();
    }
  }
  
  /* Convenience method to decrypt using key in base64 format. */
  public static final String decrypt(String encryptionSet, String base64Key) {
    byte[] keyBytes = Base64.decodeBase64(base64Key);
    return decrypt(encryptionSet, keyBytes);
  }

  /* AES/GCM decrypt plain text data given the text-based payload (EncryptionSet) 
   * containing the cipher scheme | text encoding | base64-encoded initialization vector
   * | base64-encoded encrypted data, and the AES 256-bit key.
   * Not expected to be used with binary data.
  */
  public static final String decrypt(String encryptionSet, byte[] keyBytes) {
    try {
      SecretKeySpec secretKey = new SecretKeySpec(keyBytes, CIPHER_ALGORITHM);

      String[] parts = encryptionSet.split("\\|");
      String scheme = parts[0];
      String encoding = parts[1];
      byte[] iv = Base64.decodeBase64(parts[2]);
      byte[] data = Base64.decodeBase64(parts[3]);

      AlgorithmParameterSpec params;
      if (scheme.contains("GCM")) {
        params = new GCMParameterSpec(GCM_TAG_BITLENGTH, iv);
      } else {
        params = new IvParameterSpec(iv);
      }
      Cipher cipher = Cipher.getInstance(scheme);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
      byte[] decryptedData = cipher.doFinal(data);
      return new String(decryptedData, encoding);
      
    } catch(GeneralSecurityException | UnsupportedEncodingException  e) {
      throw new RuntimeException(e);
    }
  }
  
  /* Generate a new 256-bit AES key to be stored in a keystore.
   * Returns a Base64 encoded URL-safe string.
  */
  public static final String generateAESKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    SecureRandom random = new SecureRandom();
    keyGen.init(256, random);
    return Base64.encodeBase64URLSafeString(keyGen.generateKey().getEncoded());
  }
}
