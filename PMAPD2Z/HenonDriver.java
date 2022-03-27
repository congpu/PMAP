package secureIoD_2;

public class HenonDriver {

	static int iterations = 10000;
	static ZSP groundStation;
	static Drone drone1;
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		int gs_id = 0;
		int dr_id = 1;
		int init_pid = 2;
		int init_chal = 3;
		int init_resp = 4;
		
		int loop = 0;
		while (loop < iterations) {
		
			groundStation = new ZSP(gs_id);
			drone1 = new Drone(dr_id, init_pid, init_chal);
			groundStation.registerDrone(dr_id, init_pid, init_chal, init_resp);
			System.out.println("Registered Drone 1");
			Drone drone2 = new Drone(5,6,7);
			groundStation.registerDrone(5, 6, 7, 8);
			System.out.println("Registered Drone 2");
			
			byte[][] message12;
			byte[][] message3;
			byte[][] message45;
			byte[][] message678;
			byte[][] message910;
			byte[][] message11;
			
			message12 = drone1.d2d_sendMessage12(0,6);
			System.out.println("message12");
			message3 = groundStation.d2d_sendMessage3(2, message12[0], message12[1]);
			System.out.println("Message3");
			message45 = drone1.d2d_sendMessage45(0, message3[0]);
			message678 = groundStation.d2d_sendMessage678(6, message45[0], message45[1]);
			message910 = drone2.d2d_sendMessage910(0, message678[0], message678[1], message678[2]);
			message11 = groundStation.d2d_sendMessage11(2, message910[0], message910[1]);
			drone1.d2d_decryptMessage11(message11[0]);
			drone1.d2d_generateSessionKey();
			drone2.d2d_generateSessionKey();
			System.out.println("D2D Session Keys Generated");
			
			/*
			byte[][] message1;
			byte[][] message2;
			byte[][] message34;
		
			message1 = drone1.sendMessage1(gs_id);
			message2 = groundStation.sendMessage2(0, message1[0], message1[1]);
			message34 = drone1.sendMessage34(0, message2[0], message2[1]);
		
			groundStation.generateSessionKey(message34[0], message34[1], message34[2], init_pid);	
			System.out.println("Session keys generated");*/
			loop++;
			System.out.println(loop);
		}
	}
	
	public static void d2dHenonDriver() {
		Drone drone2 = new Drone(5,6,7);
		groundStation.registerDrone(5, 6, 7, 8);
		
		byte[][] message12;
		byte[][] message3;
		byte[][] message45;
		byte[][] message678;
		byte[][] message910;
		byte[][] message11;
		
		message12 = drone1.d2d_sendMessage12(0,6);
		message3 = groundStation.d2d_sendMessage3(1, message12[0], message12[1]);
		message45 = drone1.d2d_sendMessage45(0, message3[0]);
		message678 = groundStation.d2d_sendMessage678(5, message45[0], message45[1]);
		message910 = drone2.d2d_sendMessage910(0, message678[0], message678[1], message678[2]);
		message11 = groundStation.d2d_sendMessage11(1, message910[0], message910[1]);
		drone1.d2d_decryptMessage11(message11[0]);
		drone1.d2d_generateSessionKey();
		drone2.d2d_generateSessionKey();
		System.out.println("D2D Session Keys Generated");
	}
}
