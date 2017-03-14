package feal4;

import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.Vector;

public class cryptanalysis {
	
	public static byte[] random(int nb) {
		SecureRandom random = new SecureRandom();
	    byte input[] = new byte[nb];
	    random.nextBytes(input);
	    
	    return input;
		
	}
	
	public static byte[] concat(byte[] a, byte[] b){
        int length = a.length + b.length;
        byte[] res = new byte[length];
        System.arraycopy(a, 0, res, 0, a.length);
        System.arraycopy(b, 0, res, a.length, b.length);
        return res;
    }
	
	// just to be sure of the hex value
	private static String btoh (byte[] digest) {
		BigInteger sh256 = new BigInteger(1, digest);
		String valueHex = String.format("%0" + (digest.length << 1) + "X", sh256); //length of digest in hex (X)
		return valueHex;
	}
	
	private static byte[] htob (String hex) {
		int size = hex.length();
		byte[] res = new byte[ size / 2];
		for (int i = 0 ; i < size ; i+= 2) {
			res [i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
		}
		return res;
	}
	
	public static byte[] M(byte[] W) {
		byte[] b0b1 = new byte[] { (byte) (W[0]^W[1])};
		byte[] b2b3 = new byte[] { (byte) (W[2]^W[3])};
		byte [] empty = new byte [] {0};
		
		byte[] left = concat(empty, b0b1);
		byte[] right = concat(b2b3, empty);
		byte[] full = concat(left, right);
		
		return full;
		
		}
	
	static byte rot2(byte x) {
        return (byte)(((x&255)<<2)|((x&255)>>>6));
    }
	
	static byte g0(byte a,byte b) {
        return rot2((byte)((a+b)&255));
    }

    static byte g1(byte a,byte b) {
        return rot2((byte)((a+b+1)&255));
    }	
	
	public static byte[] F(byte[] inp) {
		byte y1 =  g1( (byte)(inp[0]^inp[1]), (byte) (inp[2]^inp[3]));
		byte y2 =  g0( y1, (byte) (inp[2]^inp[3]));
		
		byte[] Y0 = new byte[] {g0(inp[0], y1)};
		byte[] Y1 = new byte[] {y1};
		byte[] Y2 = new byte[] {y2};
		byte[] Y3 = new byte[] {g1(y2, inp[3])};
		
		byte[] left = concat(Y0, Y1);
		byte[] right = concat(Y2, Y3);
		byte[] full = concat(left, right);
		
		return full;
		//AGJFGYTS
	}
	
	public static byte[] xor(byte[] a, byte[] b) {
		if (a.length == b.length) {		
			int i = 0;
			byte[] output = new byte[a.length];
			for (byte n : a)
				output[i] = (byte) (n ^ b[i++]);
			
			return output;
		}
		
		return null;		
	}
	
	  public static void writer(String name, String text) {
	        String path = "C:\\Users\\Fricorn\\workspace\\feal4\\src\\feal4\\" + name + ".txt";
	        File fi =new File(path); 
	        try {
	            fi .createNewFile();
	            final FileWriter writer = new FileWriter(fi, true);
	            try {
	                writer.write(text + "\n");
	            } finally {
	                writer.close();
	            }
	        } catch (Exception e) {
	            System.out.println("Impossible to create the file");
	        }
	    }
	
	public static void decrypt(byte[] kr) {
		byte[] p0 = random(8); //{118, -58, 26, -68, 22, -17, -95, 56}; //random(8);
		byte[] p1 = xor(p0, kr);
		
		//Given C0 et C1 via l'applet java
		//System.out.println(btoh(p1));
		//btoh(p0);
		//btoh(p1);
		
		java.awt.Toolkit.getDefaultToolkit().beep();
		//System.out.println("P0 : " + btoh(p0));
		//System.out.println("P1 : " + btoh(p1));
		
		Scanner sc = new Scanner(System.in);
		//System.out.println("C0 : ");	
		byte[] c0 = htob(sc.nextLine()); //htob("4F4472FA737920B4");
		
		//System.out.println("C1 : ");
		byte[] c1 = htob(sc.nextLine()); //htob("E3CBE1BA274E9377");
		
		
		//System.out.println("c0 : " + btoh(c0) +"\nc1 : " + btoh(c1));
		
		byte l0[] = Arrays.copyOfRange(c0, 0, 4);
		byte r0[] = Arrays.copyOfRange(c0, 4, 8);
		byte l1[] = Arrays.copyOfRange(c1, 0, 4);
		byte r1[] = Arrays.copyOfRange(c1, 4, 8);
		
		//System.out.println("l0 : " + Arrays.toString(l0));
		//System.out.println("r0 : " + Arrays.toString(r0));
		//System.out.println("l1 : " + Arrays.toString(l1));
		//System.out.println("r1 : " + Arrays.toString(r1));
		
		byte[] y0 = xor(l0, r0);
		byte[] y1 = xor(l1, r1);
		byte[] l_ = xor(l0, l1);
		byte[] z_ = xor(l_, htob("02000000"));
		
		// Contient les différentes valeurs de D
		List<String> valueOfD = new Vector<String>();
		
		//System.out.println(Arrays.toString(htob("02000000")));
		//System.out.println("y0 : " + Arrays.toString(y0));
		//System.out.println("y1 : " + Arrays.toString(y0));
		//System.out.println("l_ : " + Arrays.toString(l_));
		//System.out.println("z_ : " + Arrays.toString(z_));
		int i = 0;
		for (byte a0 = -128 ; a0 < 127 ; a0++) {
			for (byte a1 = -128 ; a1 < 127 ; a1++) {
				
				byte[] q0 = F(xor(M(y0), new byte[]{0, a0, a1, 0}));
				byte[] q1 = F(xor(M(y1), new byte[]{0, a0, a1, 0}));
				
				//System.out.println("xor : " + xor(q0,q1)[1] + "\nz_ : " + z_[1]);
				
				//if (btoh(xor(q0,q1)).substring(2, 6).equals(btoh(z_).substring(2,6))) {
				if ( xor(q0,q1)[1] == z_[1] && xor(q0,q1)[2] == z_[2]) {
					
					for (byte d0 = -128 ; d0 < 127 ; d0++) {
						for (byte d1 = -128 ; d1 < 127 ; d1++) { 
							byte[] D = new byte[] {d0, (byte) (a0^d0), (byte) (a1^d1), d1};
							byte[] Z0_ = F(xor(y0, D));
							byte[] Z1_ = F(xor(y1, D));
							
							//System.out.println("xor : " + Arrays.toString(xor(Z0_, Z1_)) + "\nz_ : " + Arrays.toString(z_));
							
							if (btoh(xor(Z0_, Z1_)).equals(btoh(z_))) {
								//System.out.println(". D : " + Arrays.toString(D));
								valueOfD.add(btoh(D));
								writer("cle1", btoh(D));
								++i;

							}
						}
					}
				}
			}
		}
		
		System.out.println(i);
		return valueOfD;		
	}
	
	
	/*public static void probableKey(List<String> keys) {
		int a = 0;
		String key = "00000000";
		for(int i=0; i<keys.size(); i++) {
			int score = 1;
			int ind = 0;
			//System.out.println(keys.get(i));
			for(int j=0; j<keys.size(); j++) {
									
				if (i != j && keys.get(i).equals(keys.get(j))) {
					score++;
					ind = i;					
				}
			}
			if (a <= score) {
				a = score;
				key = keys.get(ind);
			}
		}
		
		System.out.println("score : " + a +"\nkey : " + key);
		
            
	}*/
	
	
	public static void main(String args[]) {
		
		for (int i = 0 ; i < 12 ; i++)
			decrypt(new byte[] {-128,-128,0,0,-128,-128,0,0});
		//probableKey(test);
	}
	

}
