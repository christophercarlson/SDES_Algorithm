import java.util.Arrays;

public class SDES {

	public static void main(String[] args) {
		
		System.out.println("Raw Key:                       Plaintext:               Ciphertext:");
		
		byte key1[] = {0,0,0,0,0,0,0,0,0,0};
		byte key2[] = {1,1,1,1,1,1,1,1,1,1};
		byte key3[] = {0,0,0,0,0,1,1,1,1,1};
		byte key4[] = {1,0,0,0,1,0,1,1,1,0};
		byte key5[] = {0,0,1,0,0,1,1,1,1,1};
		
		byte plaintext1[] = {0,0,0,0,0,0,0,0}; 
		byte plaintext2[] = {1,1,1,1,1,1,1,1};
		
		byte ciphertext1[] = {0,0,0,1,1,1,0,0}; 
		byte ciphertext2[] = {1,1,0,0,0,0,1,0}; 
		byte ciphertext3[] = {1,0,0,1,1,1,0,1}; 
		byte ciphertext4[] = {1,0,0,1,0,0,0,0}; 
		
		System.out.println(Arrays.toString(key1) + " " + Arrays.toString(plaintext1) + " " + Arrays.toString(Encrypt(key1, plaintext1)));
		
		System.out.println(Arrays.toString(key2) + " " + Arrays.toString(plaintext2) + " " + Arrays.toString(Encrypt(key2, plaintext2)));
		
		System.out.println(Arrays.toString(key3) + " " + Arrays.toString(plaintext1) + " " + Arrays.toString(Encrypt(key3, plaintext1)));
		
		System.out.println(Arrays.toString(key3) + " " + Arrays.toString(plaintext2) + " " + Arrays.toString(Encrypt(key3, plaintext2)));
		
		System.out.println(Arrays.toString(key4) + " " + Arrays.toString(Decrypt(key4,ciphertext1)) + " " + Arrays.toString(ciphertext1));
		
		System.out.println(Arrays.toString(key4) + " " + Arrays.toString(Decrypt(key4,ciphertext2)) + " " + Arrays.toString(ciphertext2));
		
		System.out.println(Arrays.toString(key5) + " " + Arrays.toString(Decrypt(key5,ciphertext3)) + " " + Arrays.toString(ciphertext3));
		
		System.out.println(Arrays.toString(key5) + " " + Arrays.toString(Decrypt(key5,ciphertext4)) + " " + Arrays.toString(ciphertext4));
		
		
	}		
		public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
		
		byte[] key1 = new byte[8];
		byte[] key2 = new byte[8];
		generateKeys(rawkey, key1, key2);
		
		byte[] SBoxOutputtemp = new byte[4];
		byte[] Swap = new byte[8];
		byte[] Swap2 = new byte[8];
		byte[] SecondRound = new byte[4];
		
		//this is too take into account that some of the strings are longer than byte arrays are longer than ten.
		int size = (int) Math.ceil(plaintext.length / 8) * 8;
		byte[] ciphertext = new byte[size];
				
		for(int m = 0; m < plaintext.length; m += 8){
					
					
		byte[] subciphertext = Arrays.copyOfRange(plaintext, m, m+8);
				
		byte[] IP= {subciphertext[1],subciphertext[5],subciphertext[2],subciphertext[0],
							subciphertext[3],subciphertext[7],subciphertext[4],subciphertext[6]};
		
		SBoxOutputtemp = FKFunction(key1, IP);
		
		/* xor function on p4 right 4 bits in IP */
		for(byte i=0 ; i < 4 ; i++) {
			
			SBoxOutputtemp[i] = (byte) (SBoxOutputtemp[i] ^ IP[i]);
			
		}
		
		/*swap for IP and fk1 solution*/
		for(byte i=0 ; i < 4 ; i++) {
			Swap[i] = IP[i+4];
			
		}
		
		for(byte i=4 ; i < 8 ; i++) {
			Swap[i] = SBoxOutputtemp[i-4];
			
		} 
		
		SecondRound = FKFunction(key2, Swap);
		
		/* xor function on p4 right 4 bits in Swap */
		for(byte i=0 ; i < 4 ; i++) {
			SecondRound[i] = (byte) (SecondRound[i] ^ Swap[i]);
			
		}
		
		/*swap for Swap and fk2 solution*/
		for(byte i=0 ; i < 4 ; i++) {
			Swap2[i] = SecondRound[i];
			
		}
		
		for(byte i=4 ; i < 8 ; i++) {
			Swap2[i] = Swap[i];
			
		}
		
		byte[] IPInverse = {Swap2[3],Swap2[0],Swap2[2],Swap2[4],
				Swap2[6],Swap2[1],Swap2[7],Swap2[5]};
		
		for(int j = 0; j < 8; j++){
			ciphertext[j + m] =  IPInverse[j];
			}
		}
	
		
		return ciphertext;
		
	}

	public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
		
		byte[] key1 = new byte[8];
		byte[] key2 = new byte[8];
		generateKeys(rawkey, key1, key2);
		
		byte[] SBoxOutputtemp = new byte[4];
		byte[] Swap = new byte[8];
		byte[] Swap2 = new byte[8];
		byte[] SecondRound = new byte[4];
		
	
		//this is too take into account that some of the strings are longer than byte arrays are longer than ten.
		int size = (int) Math.ceil(ciphertext.length / 8) * 8;
		byte[] plaintext = new byte[size];
		
		for(int m = 0; m < ciphertext.length; m += 8){
			
			
			byte[] subciphertext = Arrays.copyOfRange(ciphertext, m, m+8);
		
			byte[] IP= {subciphertext[1],subciphertext[5],subciphertext[2],subciphertext[0],
					subciphertext[3],subciphertext[7],subciphertext[4],subciphertext[6]};
		
			SBoxOutputtemp = FKFunction(key2, IP);
		
			/* xor function on p4 right 4 bits in IP */
			for(byte i=0 ; i < 4 ; i++) {
			SBoxOutputtemp[i] = (byte) (SBoxOutputtemp[i] ^ IP[i]);
			
			}
			
			/*swap for IP and fk1 solution*/
			for(byte i=0 ; i < 4 ; i++) {
				Swap[i] = IP[i+4];
			
			}
		
			for(byte i=4 ; i < 8 ; i++) {
			Swap[i] = SBoxOutputtemp[i-4];
			
			}
		
			SecondRound = FKFunction(key1, Swap);
		
			/* xor function on p4 right 4 bits in Swap */
			for(byte i=0 ; i < 4 ; i++) {
				SecondRound[i] = (byte) (SecondRound[i] ^ Swap[i]);
				
			}
		
		
			/*swap for Swap and fk2 solution*/
			for(byte i=0 ; i < 4 ; i++) {
				Swap2[i] = SecondRound[i];
			
			}

			for(byte i=4 ; i < 8 ; i++) {
				Swap2[i] = Swap[i];
			
			}
		
			byte[] IPInverse = {Swap2[3],Swap2[0],Swap2[2],Swap2[4],Swap2[6],Swap2[1],Swap2[7],Swap2[5]};
			
			for(int j = 0; j < 8; j++){
				plaintext[j + m] =  IPInverse[j];
			}
		
		}
			return plaintext;
	}
	

	public static byte[] FKFunction(byte[] key, byte[] IP) {
		
		byte[] SBoxInput = new byte[8];
		byte[] SBoxOutput = new byte[4];
		byte[] SBoxOutputtemp = new byte[4];
		
		byte[] RightIP = {IP[4],IP[5],IP[6],IP[07]};
	
		byte[] EP = {RightIP[3],RightIP[0],RightIP[1],RightIP[2],
				     RightIP[1],RightIP[2],RightIP[3],RightIP[0]};
		
		for(byte i=0; i < 8 ; i++) {
			SBoxInput[i] = (byte) (EP[i] ^ key[i]);
			
		}
		 
		SBoxOutput = SBox(SBoxInput);
	
		/* Creates and returns p4*/
		SBoxOutputtemp[0]= SBoxOutput[1];
		SBoxOutputtemp[1]= SBoxOutput[3];
		SBoxOutputtemp[2]= SBoxOutput[2];
		SBoxOutputtemp[3]= SBoxOutput[0];
		
		return SBoxOutputtemp;
		
	}
	
	
	
	private static void generateKeys(byte[] rawkey, byte[] k1, byte[] k2){
		byte[] afterP10 = keyGenPermute10(rawkey);
		byte[] afterS1 = keyGenShift(afterP10, 1);
		keyGenPermute10to8(afterS1, k1);
		byte[] afterS2 = keyGenShift(afterS1, 2);
		keyGenPermute10to8(afterS2, k2);
	}
	
	private static byte[] keyGenPermute10(byte[] input){
		
		byte[] output = new byte[10];
		output[0] = input[2];
		output[1] = input[4];
		output[2] = input[1];
		output[3] = input[6];
		output[4] = input[3];
		output[5] = input[9];
		output[6] = input[0];
		output[7] = input[8];
		output[8] = input[7];
		output[9] = input[5];
		
		return output;
	}
	
	private static byte[] keyGenShift(byte[] input, int shiftAmount){
		
		byte[] output = new byte[10];
		output[0] = input[(0 + shiftAmount) % 5];
		output[1] = input[(1 + shiftAmount) % 5];
		output[2] = input[(2 + shiftAmount) % 5];
		output[3] = input[(3 + shiftAmount) % 5];
		output[4] = input[(4 + shiftAmount) % 5];
		output[5] = input[(0 + shiftAmount) % 5 + 5];
		output[6] = input[(1 + shiftAmount) % 5 + 5];
		output[7] = input[(2 + shiftAmount) % 5 + 5];
		output[8] = input[(3 + shiftAmount) % 5 + 5];
		output[9] = input[(4 + shiftAmount) % 5 + 5];
		
		return output;
	}
	
	private static void keyGenPermute10to8(byte[] input, byte[] output){
		if(input == null){
			System.out.println("Error: SDES.keyGenPermutation10to8(input, output) got null for input");
			System.exit(1);
		}
		if(output == null){
			System.out.println("Error: SDES.keyGenPermutation10to8(input, output) got null for output");
			System.exit(1);
		}
		if(input.length != 10){
			System.out.println("Error: SDES.keyGenPermutation10to8(input, output) got input of incorrect size: " + input.length + " instead of 10");
			System.exit(1);
		}		
		if(output.length != 8){
			System.out.println("Error: SDES.keyGenPermutation10to8(input, output) got output of incorrect size: " + input.length + " instead of 10");
			System.exit(1);
		}
		
		output[0] = input[5];
		output[1] = input[2];
		output[2] = input[6];
		output[3] = input[3];
		output[4] = input[7];
		output[5] = input[4];
		output[6] = input[9];
		output[7] = input[8];
	}
	
	public static byte[] SBox(byte[] SBoxinput) {
	
		String[] SBoxOutput = new String[4];
		byte[] finalOutput = new byte[4];
		
		String[][] S0 = {
		      { "01","00","11","10"},
		      {"11","10","01","00"},
		      {"00","10","01","11"},
		      {"11","01","11","10"}
		};

		String[][] S1 = {
			  {"00","01","10","11"},    
			  {"10","00","01","11"},
			  {"11","00","01","00"},
			  {"10","01","00","11"}
		};
		
		String S0RowTemp = Integer.toString(SBoxinput[0]) + Integer.toString(SBoxinput[3]);
		int S0Row = Integer.parseInt(S0RowTemp);
		int S0RowIndex = ByteToDecimal(S0Row);
		
		  
		String S0ColTemp = Integer.toString(SBoxinput[1]) + Integer.toString(SBoxinput[2]);
		int S0Col = Integer.parseInt(S0ColTemp);
		int S0ColIndex = ByteToDecimal(S0Col);

		
		SBoxOutput[0] = (String) S0[S0RowIndex][S0ColIndex];
		
		
		String S1RowTemp = Integer.toString(SBoxinput[4]) + Integer.toString(SBoxinput[7]);
		int S1Row = Integer.parseInt(S1RowTemp);
		int S1RowIndex = ByteToDecimal(S1Row);
		
		String S1ColTemp = Integer.toString(SBoxinput[5]) + Integer.toString(SBoxinput[6]);
		int S1Col = Integer.parseInt(S1ColTemp);
		int S1ColIndex = ByteToDecimal(S1Col);
	
		SBoxOutput[1] = (String) S1[S1RowIndex][S1ColIndex];
	
		String OutputTemp = (SBoxOutput[0]) + (SBoxOutput[1]);
		String[] ls = OutputTemp.split("");
		
		for(int i =0; i<4; i++) {
			finalOutput[i] = Byte.valueOf(ls[i]);
		}
	
		
		return finalOutput;
	
	}
	
	public static int ByteToDecimal(int n) {
		
		int decimal=0,p=0;
        
        while(n!=0)
        {
            decimal+=((n%10)*Math.pow(2,p));
            n=(byte) (n/10);
            p++;
        }
        
        return decimal;	
	}
	
		
	
	
	
	

}
