package secureIoD_2;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * This class contains the functions needed to shuffle and unshuffle the bytes of the messages being sent between drone and ground station.
 * @author Andrew Wall
 *
 */
public class HenonMap {
	
	private double a = 1.4;
	private double b = 0.3;
	
	/**
	 * This function shuffles the bytes of the given message using Henon map with the initial condition being the challenge-response pair.
	 * @param message is the plaintext message that is being shuffled
	 * @param crp is the challenge-response pair.
	 * @return the shuffled bytes of the message.
	 */
	public byte[] encrypt(String message, double[] crp) {
		
		double x = crp[0];										
		double y = crp[1];										
		double new_x;
		double new_y;
		int index;
		boolean loop;
		
		byte[] messageBytes;										//	Bytes of the plain text message
		messageBytes = message.getBytes(StandardCharsets.UTF_8);	// Converts the plain text message to Bytes array
		byte[] shuffledBytes = new byte[messageBytes.length];		//	Bytes of the shuffled message
		boolean[] usedIndex = new boolean[messageBytes.length];
		Arrays.fill(usedIndex, false);
		
		for (int i = 0; i < messageBytes.length; i++) {
			loop = true;
			new_x = 1 - a*x*x + y;
			new_y = b*x;
			index = (int) Math.abs(((new_x*10) + (new_y*10)) % (messageBytes.length-1));
			while (loop) {
				if (usedIndex[index] != true) {
					shuffledBytes[index] = messageBytes[i];
					usedIndex[index] = true;
					loop = false;
				}else {
					index++;
					if (index >= messageBytes.length) {
						index = 0;
					}
				}
			}
			x = new_x;
			y = new_y;
		}
		return shuffledBytes;
	}
	
	/**
	 * This function unshuffles the bytes of the given message using Henon map with the initial condition being the challenge-response pair.
	 * @param encryptedMessage is the cyphertext that is being unshuffled.
	 * @param crp is the challenge-response pair.
	 * @return the plaintext message.
	 */
	public String decrypt(byte[] encryptedMessage, double[] crp) {
		
		double x = crp[0];										
		double y = crp[1];										
		double new_x;
		double new_y;
		int index;
		boolean loop;
		
		byte[] unshuffledBytes = new byte[encryptedMessage.length];
		boolean[] usedIndex = new boolean[encryptedMessage.length];
		Arrays.fill(usedIndex, false);
		
		for (int i = 0; i < encryptedMessage.length; i++) {
			loop = true;
			new_x = 1 - a*x*x + y;
			new_y = b*x;
			index = (int) Math.abs(((new_x*10) + (new_y*10)) % (encryptedMessage.length-1));
			
			while (loop) {
				if (usedIndex[index] != true) {
					unshuffledBytes[i] = encryptedMessage[index];
					usedIndex[index] = true;
					loop = false;
				}else {
					index++;
					if (index >= encryptedMessage.length) {
						index = 0;
					}
				}
			}
			x = new_x;
			y = new_y;
		}
		return new String(unshuffledBytes, StandardCharsets.UTF_8);		// Converts the bytes array back into a string and returns the result
	}
}
