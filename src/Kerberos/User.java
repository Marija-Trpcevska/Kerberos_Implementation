package Kerberos;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;

public class User {
    private final byte[] Key;
    private byte[] session_key = new byte[16];

    public User() {
        Key = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(Key);
    }

    public byte[] getKey() {
        return Key;
    }

    public byte[] generate_nonce() {
        byte[] nonce = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        return nonce;
    }

    public ArrayList<ArrayList<byte[]>> KDC_RQST_response_parse(ArrayList<ArrayList<byte[]>> response, String sender_username, String receiver_username, byte[] nonce){
        System.out.println("IN KDC_RQST_response_parse:");
        ArrayList<byte[]> to_sender = response.get(0);
        ArrayList<byte[]> to_receiver = response.get(1);

        System.out.println("DECRYPTED LOAD FROM KDC TO "+sender_username+": ");
        byte[] session_key = AES.decrypt(to_sender.get(0), new String(Key,StandardCharsets.UTF_8));
        assert session_key != null;
        System.out.println("Decrypted session key: "+format_array(session_key));

        byte[] kdc_nonce = AES.decrypt(to_sender.get(1), new String(Key,StandardCharsets.UTF_8));
        assert kdc_nonce != null;
        System.out.println("Decrypted nonce: "+format_array(kdc_nonce));

        byte[] lifetime_bytes = AES.decrypt(to_sender.get(2), new String(Key,StandardCharsets.UTF_8));
        assert lifetime_bytes != null;
        System.out.println("Decrypted lifetime : "+new String(lifetime_bytes,StandardCharsets.UTF_8));

        byte[] receiver_bytes = AES.decrypt(to_sender.get(3), new String(Key,StandardCharsets.UTF_8));
        assert receiver_bytes != null;
        System.out.println("Decrypted receiver id (name): "+ new String(receiver_bytes,StandardCharsets.UTF_8));
        System.out.println("-------------------------------------------------------------");

        if(Arrays.equals(kdc_nonce, nonce) && new String(receiver_bytes,StandardCharsets.UTF_8).equals(receiver_username)){
            ZonedDateTime now = ZonedDateTime.now();
            ZonedDateTime lifetime = ZonedDateTime.parse(new String(lifetime_bytes,StandardCharsets.UTF_8));
            long duration = Duration.between(now, lifetime).getSeconds();
            System.out.println("Duration in seconds until expiration of lifetime: "+ duration);

            if(0< duration && duration/60 <= 30){
                System.out.println("VERIFICATION SUCCESSFUL");
                ZonedDateTime timestamp = generate_timestamp();
                System.out.println("Generated timestamp: "+timestamp.toString());
                System.out.println("-------------------------------------------------------------");
                System.out.println("ENCRYPTION WITH SESSION KEY: ");

                byte[] sender_bytes = AES.encrypt(sender_username.getBytes(StandardCharsets.UTF_8), new String(session_key, StandardCharsets.UTF_8));
                assert sender_bytes != null;
                System.out.println("Encrypted receiver id(name): "+ format_array(sender_bytes));

                byte[] timestamp_bytes = AES.encrypt(timestamp.toString().getBytes(StandardCharsets.UTF_8), new String(session_key, StandardCharsets.UTF_8));
                assert timestamp_bytes != null;
                System.out.println("Encrypted timestamp: "+format_array(timestamp_bytes));
                System.out.println("-------------------------------------------------------------");

                ArrayList<byte[]> to_receiver_from_sender = new ArrayList<>();
                to_receiver_from_sender.add(sender_bytes);
                to_receiver_from_sender.add(timestamp_bytes);
                ArrayList<ArrayList<byte[]>> response_sender = new ArrayList<>();
                response_sender.add(to_receiver_from_sender);
                response_sender.add(to_receiver);

                this.session_key = session_key;
                return response_sender;
            }
        }
        return null;
    }

    public void receiver_parse_and_verify(ArrayList<ArrayList<byte[]>> request, String sender_username, String receiver_username){
        System.out.println("IN receiver_parse_and_verify:");
        ArrayList<byte[]> to_receiver_from_sender = request.get(0);
        ArrayList<byte[]> to_receiver = request.get(1);

        System.out.println("DECRYPTED LOAD FROM KDC TO "+receiver_username+": ");
        byte[] session_key = AES.decrypt(to_receiver.get(0),new String(Key,StandardCharsets.UTF_8));
        assert session_key != null;
        System.out.println("Decrypted session key: "+format_array(session_key));

        byte[] sender_bytes_kdc = AES.decrypt(to_receiver.get(1),new String(Key,StandardCharsets.UTF_8));
        assert sender_bytes_kdc != null;
        System.out.println("Decrypted sender id(name): "+ new String(sender_bytes_kdc, StandardCharsets.UTF_8));

        byte[] lifetime_bytes = AES.decrypt(to_receiver.get(2),new String(Key,StandardCharsets.UTF_8));
        assert lifetime_bytes != null;
        System.out.println("Decrypted lifetime: "+new String(lifetime_bytes,StandardCharsets.UTF_8));
        System.out.println("-------------------------------------------------------------");
        System.out.println("DECRYPTED LOAD FROM "+sender_username+" TO "+receiver_username+": ");

        byte[] sender_bytes = AES.decrypt(to_receiver_from_sender.get(0),new String(session_key,StandardCharsets.UTF_8));
        assert sender_bytes != null;
        System.out.println("Decrypted sender id(name): "+ new String(sender_bytes, StandardCharsets.UTF_8));

        byte[] timestamp_bytes = AES.decrypt(to_receiver_from_sender.get(1),new String(session_key,StandardCharsets.UTF_8));
        assert timestamp_bytes != null;
        System.out.println("Decrypted timestamp: "+new String(timestamp_bytes,StandardCharsets.UTF_8));

        if(new String(sender_bytes_kdc,StandardCharsets.UTF_8).equals(new String(sender_bytes, StandardCharsets.UTF_8))){
            ZonedDateTime now = ZonedDateTime.now();

            ZonedDateTime lifetime = ZonedDateTime.parse(new String(lifetime_bytes,StandardCharsets.UTF_8));
            long duration_lifetime = Duration.between(now, lifetime).getSeconds();

            ZonedDateTime timestamp = ZonedDateTime.parse(new String(timestamp_bytes,StandardCharsets.UTF_8));
            long duration_timestamp = Duration.between(now, timestamp).getSeconds();

            if((0< duration_lifetime && duration_lifetime/60 <= 30) && (0< duration_timestamp && duration_timestamp/60 <= 30)){
                System.out.println("VERIFICATION SUCCESSFUL");
                this.session_key = session_key;
            }
            else{
                System.out.println("Some received data seems not to have matched during verification.");
            }
        }
    }

    public byte[] send_message(String message){
        return AES.encrypt(message.getBytes(StandardCharsets.UTF_8), new String(this.session_key, StandardCharsets.UTF_8));
    }

    public void receive_message(byte[] message){
        System.out.println("ENCRYPTED MESSAGE WITH SESSION KEY: "+format_array(message));
        byte[] decrypted = AES.decrypt(message, new String(this.session_key, StandardCharsets.UTF_8));
        assert decrypted != null;
        System.out.println("DECRYPTED MESSAGE WITH SESSION KEY: "+format_array(decrypted));
        System.out.println("RAW DECRYPTED MESSAGE: "+new String(decrypted,StandardCharsets.UTF_8));
        System.out.println("-------------------------------------------------------------");
    }

    public String format_array(byte[] array){
        StringBuilder str = new StringBuilder(" ");
        for(byte b : array){
            str.append(String.format("%x", b)).append(" ");
        }
        return String.valueOf(str);
    }

    public ZonedDateTime generate_timestamp(){
        return ZonedDateTime.now().plus(30, ChronoUnit.MINUTES);
    }

}
