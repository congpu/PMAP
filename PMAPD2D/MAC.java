package secureIoD_2;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class contains the functions used to generate the MAC verification code.
 * @author Andrew Wall
 *
 */
public class MAC {

	public byte[] generateMAC(byte[] encryptedMessage, int nonce) {
		// TODO Auto-generated method stub
		try {
			String input = encryptedMessage +" "+ nonce;
			
			MessageDigest md = MessageDigest.getInstance("MD5");
			
			byte[] messageDigest = md.digest(input.getBytes());
			
			return messageDigest;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e);
		}
	}
	
	public byte[] generateMAC(byte[] encryptedMessage, int nonce1, int nonce2) {
		// TODO Auto-generated method stub
		try {
			String input = encryptedMessage +" "+ nonce1 +" "+ nonce2;
					
			MessageDigest md = MessageDigest.getInstance("MD5");
					
			byte[] messageDigest = md.digest(input.getBytes());
					
			return messageDigest;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e);
		}
	}
	
	public byte[] generateMAC(byte[] encryptedMessage1, byte[] encryptedMessage2, int nonce1, double response) {
		// TODO Auto-generated method stub
		try {
			String input = encryptedMessage1 +" "+ encryptedMessage2 +" "+ nonce1 +" "+ response;
					
			MessageDigest md = MessageDigest.getInstance("MD5");
					
			byte[] messageDigest = md.digest(input.getBytes());
					
			return messageDigest;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e);
		}
	}

	public byte[] generateMAC(byte[] message6, byte[] message7, byte[] message8, int nonce_j, int nonce_i, int pid) {
		// TODO Auto-generated method stub
		try {
			String input = message6 +" "+ message7 +" "+ message8 +" "+ nonce_j +" "+ nonce_i +" "+ pid;
			
			MessageDigest md = MessageDigest.getInstance("MD5");
			
			byte[] messageDigest = md.digest(input.getBytes());
			
			return messageDigest;
		} catch (Exception e) {
			// TODO: handle exception
			throw new RuntimeException(e);
		}
	}
}
