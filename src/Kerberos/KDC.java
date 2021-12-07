package Kerberos;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;

public class KDC {
    HashMap<String, byte[]> KEK;
    public KDC(){
        KEK = new HashMap<>();
    }

    public void add_user_to_KDC(String user_name, byte[] key){
        KEK.put(user_name, key);
    }

    public ArrayList<ArrayList<byte[]>> RQST(String sender_user_name, String receiver_user_name, byte[] nonce){

        System.out.println("IN RQST:");
        byte[] sender_key = KEK.get(sender_user_name);
        byte[] receiver_key = KEK.get(receiver_user_name);

        if(sender_key != null && receiver_key != null){

            System.out.println("Sender: "+sender_user_name+" with key "+ format_array(sender_key));
            System.out.println("Receiver: "+receiver_user_name+" with key "+ format_array(receiver_key));

            byte[] session_key = generate_session_key(sender_key, receiver_key);
            System.out.println("Session key: "+ format_array(session_key));

            ZonedDateTime lifetime = generate_lifetime();
            System.out.println("Lifetime (30 mins from now): "+ lifetime.toString());
            byte [] lifetime_bytes = lifetime.toString().getBytes(StandardCharsets.UTF_8);
            System.out.println("Nonce: "+format_array(nonce));
            System.out.println("-------------------------------------------------------------");

            System.out.println("ENCRYPTED LOAD FOR THE SENDER:");
            byte[] session_key_sender = AES.encrypt(session_key, new String(sender_key,StandardCharsets.UTF_8));
            assert session_key_sender != null;
            System.out.println("Encrypted session_key: "+format_array(session_key_sender));

            nonce = AES.encrypt(nonce, new String(sender_key,StandardCharsets.UTF_8));
            assert nonce != null;
            System.out.println("Encrypted nonce: "+format_array(nonce));

            byte[] lifetime_bytes_sender = AES.encrypt(lifetime_bytes, new String(sender_key,StandardCharsets.UTF_8));
            assert lifetime_bytes_sender != null;
            System.out.println("Encrypted lifetime: "+format_array(lifetime_bytes_sender));

            byte[] receiver_bytes = receiver_user_name.getBytes(StandardCharsets.UTF_8);
            receiver_bytes = AES.encrypt(receiver_bytes, new String(sender_key,StandardCharsets.UTF_8));
            assert receiver_bytes != null;
            System.out.println("Encrypted receiver id (name): "+format_array(receiver_bytes));
            System.out.println("-------------------------------------------------------------");
            System.out.println("ENCRYPTED LOAD FOR THE RECEIVER:");

            ArrayList<byte[]> to_sender = new ArrayList<>();
            to_sender.add(session_key_sender);
            to_sender.add(nonce);
            to_sender.add(lifetime_bytes_sender);
            to_sender.add(receiver_bytes);


            byte[] session_key_receiver = AES.encrypt(session_key, new String(receiver_key,StandardCharsets.UTF_8));
            assert session_key_receiver != null;
            System.out.println("Encrypted session_key: "+format_array(session_key_receiver));

            byte[] sender_bytes = sender_user_name.getBytes(StandardCharsets.UTF_8);
            sender_bytes = AES.encrypt(sender_bytes, new String(receiver_key,StandardCharsets.UTF_8));
            assert sender_bytes != null;
            System.out.println("Encrypted receiver id (name): "+format_array(sender_bytes));


            byte[] lifetime_bytes_receiver = AES.encrypt(lifetime_bytes, new String(receiver_key,StandardCharsets.UTF_8));
            assert lifetime_bytes_receiver != null;
            System.out.println("Encrypted lifetime: "+format_array(lifetime_bytes_receiver));
            System.out.println("-------------------------------------------------------------");

            ArrayList<byte[]> to_receiver = new ArrayList<>();
            to_receiver.add(session_key_receiver);
            to_receiver.add(sender_bytes);
            to_receiver.add(lifetime_bytes_receiver);

            ArrayList<ArrayList<byte[]>> result = new ArrayList<>();
            result.add(to_sender);
            result.add(to_receiver);
            return result;
        }
        return null;
    }
    public String format_array(byte[] array){
        StringBuilder str = new StringBuilder(" ");
        for(byte b : array){
            str.append(String.format("%x", b)).append(" ");
        }
        return String.valueOf(str);
    }

    byte[] XOR(byte[] array1, byte[] array2){
        byte[] xor = new byte[array1.length];
        int i = 0;
        for (byte b : array1)
            xor[i] = (byte)(b ^ array2[i++]);
        return xor;
    }

    public byte[] generate_session_key(byte[] sender_key, byte[] receiver_key){
        byte[] nonce = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        return XOR(XOR(sender_key, receiver_key),nonce);
    }

    public ZonedDateTime generate_lifetime(){
        return ZonedDateTime.now().plus(30, ChronoUnit.MINUTES);
    }

}
