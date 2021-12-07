package Kerberos;

import java.util.ArrayList;

public class Main {
    public static void main(String[] args) {
        KDC KDC = new KDC();

        User Alice = new User();
        User Bob = new User();

        KDC.add_user_to_KDC( "Alice", Alice.getKey());
        KDC.add_user_to_KDC("Bob", Bob.getKey());

        byte[] nonce = Alice.generate_nonce();

        ArrayList<ArrayList<byte[]>> response = KDC.RQST("Alice", "Bob", nonce);
        ArrayList<ArrayList<byte[]>> verified_and_sent_from_sender = Alice.KDC_RQST_response_parse(response, "Alice","Bob", nonce);
        Bob.receiver_parse_and_verify(verified_and_sent_from_sender, "Alice", "Bob");

        System.out.println("-------------------------------------------------------------");
        System.out.println("FROM ALICE TO BOB:");
        String message = "Hello";
        System.out.println("RAW MESSAGE: "+message);
        byte[] encrypted_message = Alice.send_message(message);
        Bob.receive_message(encrypted_message);
    }
}
