package secureIoD_2;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

public class Drone {

	private int id;
	private int pid;
	private int pid_i;
	private int pid_j;
	private int newPid;
	private int nonce_d;
	private int nonce_z;
	private int nonce_i;
	private int nonce_j;
	private double challenge;
	private double[] crp;
	private double newChallenge;
	private double[] newCrp;
	private HenonMap shuffle;
	private Random random;
	
	private byte[] message;
	private byte[] message2;
	private byte[] message3;
	private byte[] message4;
	private byte[] message5;
	private byte[] message9;
	private byte[] message10;
	private byte[] mac;
	private MAC verify;
	private int sessionKey;
	
	/**
	 * This is the constructor to create a new Drone.
	 * @param id is the id number of the drone.
	 * @param initial_pid is the pseudonym used by the drone during communication.
	 * @param initial_challenge is the challenge that will be used during the next authentication request with the ground station.
	 */
	public Drone(int id, int initial_pid, double initial_challenge) {
		// TODO Auto-generated constructor stub
		this.id = id;
		pid = initial_pid;
		challenge = initial_challenge;
		
		shuffle = new HenonMap();
		verify = new MAC();
		
		crp = new double[2];
		newCrp = new double[2];
		
		random = new Random();
	}
	
	/**
	 * This function represents the Physical Unclonable Function that the drone uses to generate a response.
	 * @param challenge is the input for the PUF
	 * @return the response based on the PUF and the challenge given.
	 */
	private double PUF(double challenge) {
		// TODO Auto-generated method stub
		return challenge + 1;
	}
	
	/**
	 * This function generates the pseudonym used by the drone during communication.
	 * @return the pseudonym.
	 */
	private int createPID() {
		return (int) (id * PUF(challenge));
	}
	
	/**
	 * This function creates, shuffles, and sends the first message.
	 * @param id_z is the id of the ground station.
	 * @return the first message.
	 */
	public byte[][] sendMessage1(int id_z) {
		nonce_d = random.nextInt();
		crp[0] = challenge;
		crp[1] = PUF(challenge);
		
		pid = createPID();
		message = shuffle.encrypt(pid +" "+ id_z +" "+ nonce_d, crp);
		
		mac = verify.generateMAC(message, nonce_d);
		
		byte[][] send = {message, mac};
		return send;
	}
	
	/**
	 * This function decryptes message 2, verifies MAC2, generates a new CRP then, creates, shuffles, and sends the third and fourth message, and performs an XOR operation on the random numbers to generate a session key..
	 * @param id_z is the id of the ground station.
	 * @return the message containing the third and fourth message and the MAC.
	 */
	public byte[][] sendMessage34(int id_z, byte[] encryptedMessage, byte[] MAC) {
		// Decrypt message 2
		String decryptedMessage;
		decryptedMessage = shuffle.decrypt(encryptedMessage, crp);
		String[] messageSeperated = decryptedMessage.split(" ");
		nonce_z = Integer.parseInt(messageSeperated[3]);
		
		// Verify MAC2
		if (Arrays.equals(verify.generateMAC(encryptedMessage, nonce_d, nonce_z), MAC)) {
			// Generate new CRP
			nonce_d = random.nextInt();
			newChallenge = ByteBuffer.wrap(shuffle.encrypt(nonce_z +" "+ nonce_d, crp)).getDouble();
			newCrp[0] = newChallenge;
			newCrp[1] = PUF(newChallenge);
			
			// Send message 34
			message3 = shuffle.encrypt(pid +" "+ id_z +" "+ nonce_z +" "+ nonce_d, crp);
			message4 = shuffle.encrypt(pid +" "+ id_z +" "+ nonce_z +" "+ nonce_d +" "+ newCrp[1], crp);
			
			mac = verify.generateMAC(message3, message4, nonce_d, newCrp[1]);
			
			challenge = newChallenge;
			crp = newCrp;
			
			sessionKey = (nonce_d ^ nonce_z);
			
			byte[][] send = {message3, message4, mac};
			return send;
		}else {
			return null;
		}
	}
	
	// DRONE TO DRONE COMMUNICATION
	// DRONE I
	/**
	 * This function creates and sends the first and second message for drone-to-drone authentication.
	 * @param id_z is the id of the ground station.
	 * @return the message being sent to ground station.
	 */
	public byte[][] d2d_sendMessage12(int id_z, int pid_j){
		pid = createPID();
		this.pid_j = pid_j;
		nonce_d = random.nextInt();
		
		message = shuffle.encrypt(pid +" "+ id_z +" "+ nonce_d, crp);
		message2 = shuffle.encrypt(pid +" "+ id_z +" "+ nonce_d +" "+ pid_j, crp);
		
		mac = verify.generateMAC(message, message2, nonce_d, pid_j);
		
		byte[][] send = {message, message2, mac};
		return send;
	}
	
	// DRONE I
	/**
	 * This function unshuffles the bytes of the third message and extracts the ground station's random number from it.
	 * @param encryptedMessage
	 */
	public void d2d_decryptMessage3(byte[] encryptedMessage) {
		String message;
		message = shuffle.decrypt(encryptedMessage, crp);
		String[] messageSeperated = message.split(" ");
		nonce_z = Integer.parseInt(messageSeperated[4]);
	}
	
	// DRONE I
	/**
	 * This function recreates the MAC verification code sent with message three and verifies the message.
	 * @param encryptedMessage
	 * @param MAC
	 * @return
	 */
	public boolean d2d_verifyMAC3(byte[] encryptedMessage, byte[] MAC) {
		if (Arrays.equals(verify.generateMAC(encryptedMessage, nonce_d, nonce_z), MAC)) {
			return true;
		}else {
			return false;
		}
	}
	
	// DRONE I
	/**
	 * This function creates and sends messages four and five and generates the new challenge-response pair for this drone.
	 * @param id_z
	 * @return
	 */
	public byte[][] d2d_sendMessage45(int id_z, byte[] encryptedMessage) {
		String message;
		message = shuffle.decrypt(encryptedMessage, crp);
		String[] messageSeperated = message.split(" ");
		nonce_z = Integer.parseInt(messageSeperated[4]);
		
		// Generates new CRP
		nonce_d = random.nextInt();
		newChallenge = ByteBuffer.wrap(shuffle.encrypt(nonce_z +" "+ nonce_d, crp)).getDouble();
		newCrp[0] = newChallenge;
		newCrp[1] = PUF(newChallenge);
		
		newPid = createPID();
		message4 = shuffle.encrypt(pid +" "+ id_z +" "+ pid_j +" "+ nonce_z +" "+ nonce_d, crp);
		message5 = shuffle.encrypt(pid +" "+ id_z +" "+ pid_j +" "+ nonce_z +" "+ nonce_d +" "+ newCrp[1], crp);
		
		mac = verify.generateMAC(message4, message5, nonce_d, newCrp[1]);
		
		challenge = newChallenge;
		crp = newCrp;
		pid = newPid;
		
		nonce_i = nonce_d;
		
		byte[][] send = {message4, message5, mac};
		return send;
	}
	
	// DRONE J
	/**
	 * This function unshuffles messages six, seven, and eight from ground station and extracts the random number and pid from drone i.
	 * @param encryptedMessage6
	 * @param encryptedMessage7
	 * @param encryptedMessage8
	 */
	public void d2d_decryptMessage678(byte[] encryptedMessage6, byte[] encryptedMessage7, byte[] encryptedMessage8) {
		String message6;
		message6 = shuffle.decrypt(encryptedMessage6, crp);
		String[] messageSeperated = message6.split(" ");
		nonce_z = Integer.parseInt(messageSeperated[2]);
		
		String message7;
		message7 = shuffle.decrypt(encryptedMessage7, crp);
		messageSeperated = message7.split(" ");
		nonce_i = Integer.parseInt(messageSeperated[3]);
		
		String message8;
		message8 = shuffle.decrypt(encryptedMessage8, crp);
		messageSeperated = message8.split(" ");
		pid_i = Integer.parseInt(messageSeperated[4]);
	}
	
	// DRONE J
	/**
	 * This function recreates and verifies the MAC sent with messages six, seven, and eight.
	 * @param encryptedMessage6
	 * @param encryptedMessage7
	 * @param encryptedMessage8
	 * @param MAC
	 * @return
	 */
	public boolean d2d_verifyMAC678(byte[] encryptedMessage6, byte[] encryptedMessage7, byte[] encryptedMessage8, byte[] MAC) {
		if (Arrays.equals(verify.generateMAC(encryptedMessage6, encryptedMessage7, encryptedMessage8, nonce_z, nonce_i, pid_i), MAC)) {
			return true;
		}else {
			return false;
		}
	}
	
	// DRONE J
	/**
	 * This function creates and sends messages nine and ten to ground station.
	 * @param id_z
	 * @return
	 */
	public byte[][] d2d_sendMessage910(int id_z, byte[] encryptedMessage6, byte[] encryptedMessage7, byte[] encryptedMessage8) {
		String message6;
		message6 = shuffle.decrypt(encryptedMessage6, crp);
		String[] messageSeperated = message6.split(" ");
		nonce_z = Integer.parseInt(messageSeperated[2]);
		
		String message7;
		message7 = shuffle.decrypt(encryptedMessage7, crp);
		messageSeperated = message7.split(" ");
		nonce_i = Integer.parseInt(messageSeperated[3]);
		
		String message8;
		message8 = shuffle.decrypt(encryptedMessage8, crp);
		messageSeperated = message8.split(" ");
		pid_i = Integer.parseInt(messageSeperated[4]);
		
		// Generates new CRP
		nonce_d = random.nextInt();
		newChallenge = ByteBuffer.wrap(shuffle.encrypt(nonce_z +" "+ nonce_d, crp)).getDouble();
		newCrp[0] = newChallenge;
		newCrp[1] = PUF(newChallenge);
		
		message9 = shuffle.encrypt(pid_j +" "+ id_z +" "+ pid_i +" "+ nonce_z +" "+ nonce_d, crp);
		message10 = shuffle.encrypt(pid_j +" "+ id_z +" "+ pid_i +" "+ nonce_z +" "+ nonce_d +" "+ newCrp[1], crp);
		
		mac = verify.generateMAC(message9, message10, nonce_d, crp[1]);
		
		challenge = newChallenge;
		crp = newCrp;
		
		nonce_j = nonce_d;
		
		byte[][] send = {message9, message10, mac};
		return send;
	}
	
	// DRONE I
	/**
	 * This function unshuffles message eleven and extracts the random number from drone j.
	 * @param encryptedMessage11
	 */
	public void d2d_decryptMessage11(byte[] encryptedMessage11) {
		String message11;
		message11 = shuffle.decrypt(encryptedMessage11, crp);
		String[] messageSeperated = message11.split(" ");
		nonce_j = Integer.parseInt(messageSeperated[4]);
	}
	
	// DRONE I
	/**
	 * This function recreates and verifies the MAC code sent with message 11.
	 * @param encryptedMessage11
	 * @param MAC
	 * @return
	 */
	public boolean d2d_verifyMAC11(byte[] encryptedMessage11, byte[] MAC) {
		if (Arrays.equals(verify.generateMAC(encryptedMessage11, nonce_i, nonce_j), MAC)) {
			return true;
		}else {
			return false;
		}
	}
	
	// DRONE I AND J
	/**
	 * This function generates the session key using the random numbers created by drones i and j.
	 */
	public void d2d_generateSessionKey() {
		sessionKey = (nonce_i ^ nonce_j);
	}
}