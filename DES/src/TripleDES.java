import java.util.Arrays;

public class TripleDES {
	public static void main(String[] args) {
		
		byte key1[] = {0,0,0,0,0,0,0,0,0,0};
		byte key2[] = {1,1,1,1,1,1,1,1,1,1};
		byte key3[] = {1,0,0,0,1,0,1,1,1,0};
		byte key4[] = {0,1,1,0,1,0,1,1,1,0};
		byte key5[] = {1,0,1,1,1,0,1,1,1,1};
		
		byte plaintext1[] = {0,0,0,0,0,0,0,0}; 
		byte plaintext2[] = {1,1,0,1,0,1,1,1};
		byte plaintext3[] = {1,0,1,0,1,0,1,0};
		
		byte ciphertext1[] = {1,1,1,0,0,1,1,0}; 
		byte ciphertext2[] = {0,1,0,1,0,0,0,0}; 
		byte ciphertext3[] = {1,0,0,0,0,0,0,0}; 
		byte ciphertext4[] = {1,0,0,1,0,0,1,0};
		
		SDES SDES = new SDES();
		
		
		System.out.println("Raw Key 1                      Raw Key 2                        Plaintext                Ciphertext");
		
		System.out.println(Arrays.toString(key1) + " " + Arrays.toString(key1) + " " + Arrays.toString(plaintext1) + " " + Arrays.toString(Encrypt(key1, key1, plaintext1)));
		System.out.println(Arrays.toString(key3) + " " + Arrays.toString(key4) + " " + Arrays.toString(plaintext2) + " " + Arrays.toString(Encrypt(key3, key4, plaintext2)));
		System.out.println(Arrays.toString(key3) + " " + Arrays.toString(key4) + " " + Arrays.toString(plaintext3) + " " + Arrays.toString(Encrypt(key3, key4, plaintext3)));
		System.out.println(Arrays.toString(key2) + " " + Arrays.toString(key2) + " " + Arrays.toString(plaintext3) + " " + Arrays.toString(Encrypt(key2, key2, plaintext3)));
		System.out.println(Arrays.toString(key3) + " " + Arrays.toString(key4) + " " + Arrays.toString(Decrypt(key3, key4, ciphertext1)) + " " + Arrays.toString(ciphertext1));
		System.out.println(Arrays.toString(key5) + " " + Arrays.toString(key4) + " " + Arrays.toString(Decrypt(key5, key4, ciphertext2)) + " " + Arrays.toString(ciphertext2));
		System.out.println(Arrays.toString(key1) + " " + Arrays.toString(key1) + " " + Arrays.toString(Decrypt(key1, key1, ciphertext3)) + " " + Arrays.toString(ciphertext3));
		System.out.println(Arrays.toString(key2) + " " + Arrays.toString(key2) + " " + Arrays.toString(Decrypt(key2, key2, ciphertext4)) + " " + Arrays.toString(ciphertext4));
		
		
				 
	}
	
	public static byte[] Encrypt( byte[] rawkey1, byte[] rawkey2, byte[] plaintext ){
		return SDES.Encrypt(rawkey1, SDES.Decrypt(rawkey2, SDES.Encrypt(rawkey1, plaintext)));
	}
	public static byte[] Decrypt( byte[] rawkey1, byte[] rawkey2, byte[] ciphertext ){
		return SDES.Decrypt(rawkey1, SDES.Encrypt(rawkey2, SDES.Decrypt(rawkey1, ciphertext)));
	}

}
	
	
