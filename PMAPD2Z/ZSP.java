package secureIoD_2;

import java.nio.ByteBuffer;
import java.security.MessageDigestSpi;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

/**
 * This class contains all the functions for the Ground Station.
 * @author Andrew Wall
 *
 */
public class ZSP {
	
	private int id;
	private int index;
	private int nonce_d;
	private int nonce_z;
	private int nonce_i;
	private int nonce_j;
	private double[] crp;
	private double[] crp2;
	private int pid_j;
	
	private Entry[] database;
	private Entry currentEntry;
	private Entry droneEntry1;
	private Entry droneEntry2;
	private int databasePosition;
	private HenonMap shuffle;
	private MAC verify;
	private Random random;
	
	private byte[] message;
	private byte[] mac;
	
	private double newChallenge;
	private double newResponse;
	private double newPid;
	private int sessionKey;
	
	private BlockChain chain;
	private ArrayList<String> transactions;
	private Date date;
	private Timestamp timestamp;

	/**
	 * This is the constructor to create a new Ground Station.
	 * @param id is the Ground Station's id number.
	 */
	public ZSP(int id) {
		// TODO Auto-generated constructor stub
		this.id = id;
		shuffle = new HenonMap();
		verify = new MAC();
		database = new Entry[10];
		databasePosition = 0;
		crp = new double[2];
		crp2 = new double[2];
		random = new Random();
		
		chain = new BlockChain(id);
		chain.generateGenesisBlock(id);
		transactions = new ArrayList<String>();
	}
	
	/**
	 * This function is used to register a new drone, during the system deployment phase.
	 * @param drone_id is the real identity of the drone
	 * @param pid is a pseudonym used by the drone during communication
	 * @param challenge
	 * @param response
	 */
	public void registerDrone(int drone_id, int pid, double challenge, double response) {
		database[databasePosition] = new Entry(pid, drone_id, challenge, response);
		databasePosition++;
	}
	
	/**
	 * This function locates the PID in the database. If the PID is not found, the authentication request is rejected.
	 * @param pid
	 * @return
	 */
	public boolean verifyPID(int pid) {
		index = 0;
		boolean loop = true;
		while (loop) {
			if (database[index].getPid() == pid) {
				loop = false;
			}
			if (index >= database.length) {
				return false;
			}
		}
		return true;
	}
	
	/**
	 * This function retrieves the drone's entry in the database for easy access throughout the authentication process.
	 * @return
	 */
	public Entry fetchEntry() {
		currentEntry = database[index];
		return currentEntry;
	}
	
	// DRONE TO ZSP MUTUAL AUTHENTICATION CODE --------------------------------------------------------------------------------------------------------------------------------
	
	/**
	 * This function decrypts message 1, verifies the MAC, then creates, shuffles, and sends the second message.
	 * @param pid is the id of the drone.
	 * @return the message containing the second message and the MAC.
	 */
	public byte[][] sendMessage2(int pid, byte[] encryptedMessage, byte[] MAC) {
		fetchEntry();
		// Decrypt message 1
		crp[0] = currentEntry.getChallenge();
		crp[1] = currentEntry.getResponse();
		
		String decryptedMessage;
		decryptedMessage = shuffle.decrypt(encryptedMessage, crp);
		String[] messageSeperated = decryptedMessage.split(" ");
		nonce_d = Integer.parseInt(messageSeperated[2]);
		
		// Verify message 1
		if (Arrays.equals(verify.generateMAC(encryptedMessage, nonce_d), MAC)) {
			// Send message 2
			nonce_z = random.nextInt();
			double[] crp = {currentEntry.getChallenge(), currentEntry.getResponse()};
			
			message = shuffle.encrypt(pid +" "+ id +" "+ nonce_d +" "+ nonce_z, crp);
			
			mac = verify.generateMAC(message, nonce_d, nonce_z);
			
			byte[][] send = {message, mac};
			return send;
		}else {
			return null;
		}
	}

	/**
	 * This function performs an XOR operation on the random numbers to generate a session key.
	 */
	public void generateSessionKey(byte[] encryptedMessage3, byte[] encryptedMessage4, byte[] MAC, int pid) {
		// Decrypt message34
		String message3;
		message3 = shuffle.decrypt(encryptedMessage3, crp);
		String[] messageSeperated = message3.split(" ");
		nonce_d = Integer.parseInt(messageSeperated[3]);
		
		String message4;
		message4 = shuffle.decrypt(encryptedMessage4, crp);
		messageSeperated = message4.split(" ");
		newResponse = Double.parseDouble(messageSeperated[4]);
		
		// Verify MAC34
		if (Arrays.equals(verify.generateMAC(encryptedMessage3, encryptedMessage4, nonce_d, newResponse), MAC)) {
			// Update entry
			if (verifyPID(pid)) {
				fetchEntry();
				double[] crp = {currentEntry.getChallenge(), currentEntry.getResponse()};
				currentEntry.setChallenge(ByteBuffer.wrap(shuffle.encrypt(nonce_z +" "+ nonce_d, crp)).getDouble());
				currentEntry.setPid((int)(currentEntry.getId() * newResponse));
				database[index] = currentEntry;
				
				// Generate session key
				sessionKey = (nonce_d ^ nonce_z);
			}else {
				return;
			}
		}else {
			return;
		}
	}
	
	// DRONE TO DRONE MUTUAL AUTHENTICATION CODE ------------------------------------------------------------------------------------------------------------------------------
	
	/**
	 * This function unshuffles messages one and two from drone i and extracts a random number and the pid of drone j.
	 * @param pid
	 * @param encryptedMessage1
	 * @param encryptedMessage2
	 */
	public void d2d_decryptMessage12(int pid, byte[] encryptedMessage1, byte[] encryptedMessage2) {
		if (!verifyPID(pid)) return;
		droneEntry1 = fetchEntry();
		crp[0] = droneEntry1.getChallenge();
		crp[1] = droneEntry1.getResponse();
		
		String message1;
		message1 = shuffle.decrypt(encryptedMessage1, crp);
		String[] messageSeperated = message1.split(" ");
		nonce_d = Integer.parseInt(messageSeperated[2]);
		
		String message2;
		message2 = shuffle.decrypt(encryptedMessage2, crp);
		messageSeperated = message2.split(" ");
		pid_j = Integer.parseInt(messageSeperated[3]);
		
		if (!verifyPID(pid_j)) return;
		droneEntry2 = fetchEntry();
	}
		
	/**
	 * This function recreates and verifies the MAC code sent with messages one and two.
	 * @param encryptedMessage1
	 * @param encryptedMessage2
	 * @param MAC
	 * @return
	 */
	public boolean d2d_verifyMAC12(byte[] encryptedMessage1, byte[] encryptedMessage2, byte[] MAC) {
		if (Arrays.equals(verify.generateMAC(encryptedMessage1, encryptedMessage2, nonce_d, pid_j), MAC)) {
			return true;
		}else {
			return false;
		}
	}
		
	/**
	 * This function generates two random numbers, then creates and sends message three to drone i.
	 * @param pid
	 * @return
	 */
	public byte[][] d2d_sendMessage3(int pid, byte[] encryptedMessage1, byte[] encryptedMessage2){
		if (!verifyPID(pid)) return null;
		droneEntry1 = fetchEntry();
		crp[0] = droneEntry1.getChallenge();
		crp[1] = droneEntry1.getResponse();
		String[] messageSeperated;
		try {
			String message1;
			message1 = shuffle.decrypt(encryptedMessage1, crp);
			messageSeperated = message1.split(" ");
			nonce_d = Integer.parseInt(messageSeperated[2]);
		} catch (Exception e) {
			// TODO: handle exception
			nonce_d = 1;
		}
		
		String message2;
		message2 = shuffle.decrypt(encryptedMessage2, crp);
		messageSeperated = message2.split(" ");
		pid_j = Integer.parseInt(messageSeperated[3]);
		
		if (!verifyPID(pid_j)) return null;
		droneEntry2 = fetchEntry();
		System.out.println("second verify");
		
		nonce_i = random.nextInt();
		nonce_j = random.nextInt();
		
		byte[] message = shuffle.encrypt(pid +" "+ id +" "+ pid_j +" "+ nonce_d +" "+ nonce_i, crp);
		System.out.println("message");
		byte[] mac = verify.generateMAC(message, nonce_d, nonce_i);
		
		byte[][] send = {message, mac};
		return send;
	}
		
	/**
	 * This function unshuffles the messages four and five from drone i and extracts the random number and new response from the message.
	 * @param pid
	 * @param encryptedMessage4
	 * @param encryptedMessage5
	 */
	public void d2d_decryptMessage45(int pid, byte[] encryptedMessage4, byte[] encryptedMessage5) {
		String message4;
		message4 = shuffle.decrypt(encryptedMessage4, crp);
		String[] messageSeperated = message4.split(" ");
		nonce_d = Integer.parseInt(messageSeperated[4]);
		
		String message5;
		message5 = shuffle.decrypt(encryptedMessage5, crp);
		messageSeperated = message5.split(" ");
		newResponse = Double.parseDouble(messageSeperated[5]);
	}
	
	/**
	 * This function recreates and verifies the MAC code sent with messages four and five.
	 * @param encryptedMessage4
	 * @param encryptedMessage5
	 * @param MAC
	 * @return
	 */
	public boolean d2d_verifyMAC45(byte[] encryptedMessage4, byte[] encryptedMessage5, byte[] MAC) {
		if (Arrays.equals(verify.generateMAC(encryptedMessage4, encryptedMessage5, nonce_d, newResponse), MAC)) {
			return true;
		}else {
			return false;
		}
	}
	
	/**
	 * This function creates messages six, seven, and eight containing the random number from ground station, the random number from drone i and the pid for drone i and sends them to drone j.
	 * @param pid
	 * @return
	 */
	public byte[][] d2d_sendMessage678(int pid, byte[] encryptedMessage4, byte[] encryptedMessage5){
		String message4;
		message4 = shuffle.decrypt(encryptedMessage4, crp);
		String[] messageSeperated = message4.split(" ");
		nonce_d = Integer.parseInt(messageSeperated[4]);
		
		String message5;
		message5 = shuffle.decrypt(encryptedMessage5, crp);
		messageSeperated = message5.split(" ");
		newResponse = Double.parseDouble(messageSeperated[5]);
		
		crp2[0] = droneEntry2.getChallenge();
		crp2[1] = droneEntry2.getResponse();
		
		byte[] message6 = shuffle.encrypt(pid_j +" "+ id +" "+ nonce_j, crp2);
		byte[] message7 = shuffle.encrypt(pid_j +" "+ id +" "+ nonce_j +" "+ nonce_d, crp2);
		byte[] message8 = shuffle.encrypt(pid_j +" "+ id +" "+ nonce_j +" "+ nonce_d +" "+ droneEntry1.getPid(), crp2);
		byte[] mac = verify.generateMAC(message6, message7, message8, nonce_j, nonce_i, droneEntry1.getPid());
		
		byte[][] send = {message6, message7, message8, mac};
		return send;
	}
	
	/**
	 * This function updates the entry for drone i in the database with the new challenge-response pair.
	 * @param pid
	 */
	public void d2d_updateEntry1(int pid) {
		if (verifyPID(pid)) {
			fetchEntry();
			double[] crp = {currentEntry.getChallenge(), currentEntry.getResponse()};
			currentEntry.setChallenge(ByteBuffer.wrap(shuffle.encrypt(nonce_i +" "+ nonce_d, crp)).getDouble());
			currentEntry.setPid((int)(currentEntry.getId() * newResponse));
			database[index] = currentEntry;
		}else {
			return;
		}
	}
	
	/**
	 * This function unshuffles messages nine and ten from drone j and extracts the random number and new response.
	 * @param pid
	 * @param encryptedMessage9
	 * @param encryptedMessage10
	 */
	public void d2d_decryptMessage910(int pid, byte[] encryptedMessage9, byte[] encryptedMessage10) {
		String message9;
		message9 = shuffle.decrypt(encryptedMessage9, crp);
		String[] messageSeperated = message9.split(" ");
		nonce_d = Integer.parseInt(messageSeperated[4]);
		
		String message10;
		message10 = shuffle.decrypt(encryptedMessage10, crp);
		messageSeperated = message10.split(" ");
		newResponse = Integer.parseInt(messageSeperated[5]);
	}
	
	/**
	 * This function recreates and verifies the MAC code sent with messages nine and ten.
	 * @param encryptedMessage9
	 * @param encryptedMessage10
	 * @param MAC
	 * @return
	 */
	public boolean d2d_verifyMAC910(byte[] encryptedMessage9, byte[] encryptedMessage10, byte[] MAC) {
		if (Arrays.equals(verify.generateMAC(encryptedMessage9, encryptedMessage10, nonce_d, newResponse), MAC)) {
			return true;
		}else {
			return false;
		}
	}
	
	/**
	 * This function updates the entry for drone j in the database with the new challenge-response pair.
	 * @param pid
	 */
	public void d2d_updateEntry2(int pid) {
		if (verifyPID(pid)) {
			fetchEntry();
			double[] crp = {currentEntry.getChallenge(), currentEntry.getResponse()};
			currentEntry.setChallenge(ByteBuffer.wrap(shuffle.encrypt(nonce_j +" "+ nonce_d, crp)).getDouble());
			currentEntry.setPid((int)(currentEntry.getId() * newResponse));
			database[index] = currentEntry;
		}else {
			return;
		}
	}
	
	/**
	 * This function creates and sends message eleven to drone i containing the random number from drone j.
	 * @param pid
	 * @return
	 */
	public byte[][] d2d_sendMessage11(int pid, byte[] encryptedMessage9, byte[] encryptedMessage10){
		String message9;
		message9 = shuffle.decrypt(encryptedMessage9, crp);
		String[] messageSeperated = message9.split(" ");
		nonce_d = Integer.parseInt(messageSeperated[4]);
		
		String message10;
		message10 = shuffle.decrypt(encryptedMessage10, crp);
		messageSeperated = message10.split(" ");
		newResponse = Integer.parseInt(messageSeperated[5]);
		
		byte[] message11 = shuffle.encrypt(pid +" "+ id +" "+ pid_j +" "+ nonce_i +" "+ nonce_d, crp);
		byte[] mac = verify.generateMAC(message11, nonce_i, nonce_d);
		
		byte[][] send = {message11, mac};
		return send;
	}
	
	// BLOCKCHAIN STORAGE MECHANISM CODE --------------------------------------------------------------------------------------------------------------------------------------
	
	/**
	 * This function adds data to the transaction ledger that will be added to the blockchain.
	 * @param data
	 */
	public void collectData(String data) {
		transactions.add(data);
	}
	
	/**
	 * This function packs the data in the transaction ledger into a block and attempts to add the block to the blockchain.
	 * @param difficulty
	 */
	public void storeData(int difficulty) {
		date = new Date();
		timestamp = new Timestamp(date.getTime());
		Block block = new Block(id, timestamp, (chain.getLatestBlock()).getHash(), transactions);
		chain.addBlock(block, difficulty);
		transactions.clear();
		// DISTRIBUTE TO OTHER ZSPs WITH DIGITAL SIGNATURE
	}

	public int getId() {
		return id;
	}

	/**
	 * This function returns the blockchain stored on this ZSP
	 * @return
	 */
	public ArrayList<Block> getChain() {
		return chain.getBlockChain();
	}

	/**
	 * This function returns the transactions that have not been added to the blockchain yet.
	 * @return
	 */
	public ArrayList<String> getTransactions() {
		return transactions;
	}
	
}

class Entry {
	private int pid;
	private int id;
	private double challenge;
	private double response;
	
	/**
	 * This constructor is used to make a new entry
	 * @param initial_pid is the pseudonym used by the drone.
	 * @param id is the drone's id number.
	 * @param initial_challenge is the challenge used for authenticating the drone with the ground station.
	 * @param initial_response is the response used for authenticating the drone with the ground station.
	 */
	public Entry(int initial_pid, int id, double initial_challenge, double initial_response) {
		// TODO Auto-generated constructor stub
		pid = initial_pid;
		this.id = id;
		challenge = initial_challenge;
		response = initial_response;
	}
	
	public int getPid() {
		return pid;
	}

	public void setPid(int pid) {
		this.pid = pid;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public double getChallenge() {
		return challenge;
	}

	public void setChallenge(double challenge) {
		this.challenge = challenge;
	}

	public double getResponse() {
		return response;
	}

	public void setResponse(double response) {
		this.response = response;
	}
}