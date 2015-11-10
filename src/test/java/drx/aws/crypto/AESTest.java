package drx.aws.crypto;

import static org.junit.Assert.*;

/**
 *
 * @author Dave
 */
public class AESTest {
  
  /**
   * Test of encrypt method, of class AES.
   */
  @org.junit.Test
  public void testEncrypt_String_String() {
    String plainText = "unit test";
    String base64Key = "h2k2cH6ZpjbRjOb1tAvE5Xg58FHUvdYhZ1cc-8POt7U";
    String encrResult1 = AES.encrypt(plainText, base64Key);
    String encrResult2 = AES.encrypt(plainText, base64Key);
    System.out.println(encrResult1);
    assertFalse(encrResult1.equals(encrResult2));
    String decrResult1 = AES.decrypt(encrResult1, base64Key);
    String decrResult2 = AES.decrypt(encrResult2, base64Key);
    assertEquals(decrResult1, decrResult2);
    assertEquals(decrResult1, plainText);
  }

  /**
   * Test of generateAESKey method, of class AES.
   */
  @org.junit.Test
  public void testGenerateAESKey() throws Exception {
    String result = AES.generateAESKey();
    System.out.println("generateAESKey "+result.length()+","+result);
    assertNotNull(result);
    assertTrue(result.length()==43);
  }
  
}
