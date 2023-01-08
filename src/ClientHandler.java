import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;

public class ClientHandler extends Thread {

    //a thread for each client

    //the class handle the received message
    //and send the messages to the same client
    Socket client ;
    SecretKey KEY;
    byte[] dataSignature;
    public boolean isOn ;
    DataInputStream inputStream ;
    DataOutputStream outputStream ;
    ObjectOutputStream objectOutputStream;
    ObjectInputStream objectInputStream;
    String clientNumber ;
    String clientPassword ;
    PublicKey publicKeyClient;
    SecretKey sessionKey;
    //BufferedReader inputStream ;
    //PrintWriter outputStream ;
    String connectionNumber ;
    String name ;
    final ArrayList<String> receivedMessages = new ArrayList<>() ;

    /*void INITCRYPTO(String KEY1 , String KEY2 , String IV1 ,String IV2 ){
        this.KEY1 = KEY1;
        this.KEY2 = KEY2;
        this.IV1 = IV1;
        this.IV2 = IV2;
    }*/
    ClientHandler(Socket clientSocket)
    {
        client = clientSocket ;
        isOn=true ;
        clientNumber = "";
        clientPassword = "" ;


        try {
            inputStream = new DataInputStream(client.getInputStream()) ;
            outputStream = new DataOutputStream(client.getOutputStream()) ;
            objectInputStream = new ObjectInputStream(client.getInputStream());
            //inputStream = new BufferedReader(new InputStreamReader(client.getInputStream())) ;
            //outputStream = new PrintWriter((client.getOutputStream())) ;

            try {

                //read the information of the clients
           /* this.clientNumber = inputStream.readUTF() ;
            this.clientPassword = inputStream.readUTF() ;
            this.connectionNumber = inputStream.readUTF() ;*/
                String register ;
                int i =0 ;
                while (inputStream!=null)
                {
                    System.out.println("IN WHILE");
                    register = inputStream.readUTF() ;
                    if (i==0)
                    {
                        System.out.println("this is first message");
                        this.clientNumber = register ;
                        System.out.println("The client number : " + this.clientNumber);
                        i++ ;
                    }

                    else if (i==1)
                    {
                        System.out.println("this is second message");
                        this.clientPassword = register ;
                        System.out.println("The client password : " + this.clientPassword);
                        i++ ;
                    }

                    if (i==2)
                        break;
                }
                this.publicKeyClient = (PublicKey) objectInputStream.readObject();
                //System.out.println("this is public Key for Client : " + publicKeyClient);

            }catch (IOException | ClassNotFoundException ex)
            {
                ex.printStackTrace();
            }
        }catch (IOException ex)
        {
            ex.printStackTrace();
        }
    }

    public SecretKey getKEY(){return KEY;}
    public SecretKey receiveKey() throws Exception {
        this.KEY = Crypto.createAESKey(this.getClientNumber());
        return this.KEY;
    }
    @Override
    public void run() {
        try {
            String str ="";
            int i = 0;
            //Received the messages from the current client(in this class)
            //check Signature For Client
            while (isOn)
            {
                if(i%2!=0){
                  String dataSignOld =inputStream.readUTF();
                  if(Crypto.VERIFYINGSIGN(DatatypeConverter.parseHexBinary(dataSignOld),str,publicKeyClient)){
                      System.out.println("Signature Success For Client!!");
                      System.out.println("The Message From Client after decrypt it : " + str);
                      synchronized (receivedMessages)
                      {
                          receivedMessages.add(str);
                      }
                  }else {
                      System.out.println("Signature Failure For Client!!");
                      throw new Exception("Signature Failure For Client");
                  }
                }else{
                    str = inputStream.readUTF() ;
                    str = Crypto.decrypt(str,KEY);
                }
                i++;
            }
        }catch (Exception ex )
        {
            ex.printStackTrace();
        }
        /*if (outputStream!=null) {
            try {
                outputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            if (inputStream!=null)
            inputStream.close();

        }catch (IOException ex)
        {
            ex.printStackTrace();
        }

        try {
            if (client!=null)
            client.close();

        }catch (IOException ex)
        {
            ex.printStackTrace();
        }*/
    }

    public PublicKey getPublicKey() {
        return publicKeyClient;
    }

    public void sendMessage(String message)
    {
        try {
            if (isOn)
                outputStream.writeUTF(message);
        } catch (IOException e) {
            e.printStackTrace();
        }



    }

    public void closeAll()
    {
        isOn = false ;
        receivedMessages.clear();
        try {inputStream.close();}catch (Exception e){}
        try {outputStream.close();}catch (Exception e){}
        try {client.close();}catch (Exception e){}
    }

    public String getClientNumber()
    {
        return clientNumber ;
    }
    public String getConnectionNumber()
    {
        return  connectionNumber ;
    }
    public String getClientPassword()
    {
        return clientPassword ;
    }
    public ArrayList<String> getReceivedMessages()
    {
        return receivedMessages;
    }



    public void makeConnectionWithAnotherClient(ClientHandler otherClient , PrivateKey privateKeyServer) throws IOException
    {


        Thread handleMessages = new Thread(){
            @Override
            public void run() {

                ArrayList<String> messages = new ArrayList<>();
                while (true) {

                    messages = getReceivedMessages() ;
                    if (!messages.isEmpty()) {
                        synchronized (messages) {
                            for (int i = 0; i < messages.size(); i++) {
                                //send the messages to the other client
                                try {
                                    //otherClient.sendMessage(messages.get(i));
                                    dataSignature = Crypto.CalculationSignature(privateKeyServer,messages.get(i));
                                    System.out.println("The Signature is : " + DatatypeConverter.printHexBinary(dataSignature));
                                    String data = Crypto.encrypt(messages.get(i),otherClient.KEY);
                                    System.out.println("The Message Encrypted  is : " + data);
                                    otherClient.sendMessage(data);
                                    otherClient.sendMessage(DatatypeConverter.printHexBinary(dataSignature));
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                            messages.clear();
                        }
                    }


                    //Received the messages from the first client(clientHandler2)
                    messages = otherClient.getReceivedMessages();
                    if (!messages.isEmpty()) {
                        synchronized (messages) {
                            for (int i = 0; i < messages.size(); i++) {
                                //send the messages to the other client
                                try {
                                    dataSignature = Crypto.CalculationSignature(privateKeyServer,messages.get(i));
                                    System.out.println("The Signature is : " + DatatypeConverter.printHexBinary(dataSignature));
                                    String data = Crypto.encrypt(messages.get(i),KEY);
                                    System.out.println("The Message Encrypted  is : " + data);
                                    sendMessage(data);
                                    sendMessage(DatatypeConverter.printHexBinary(dataSignature));
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                            messages.clear();
                        }
                    }
                    try {
                        Thread.sleep(5);
                    }catch (InterruptedException ex)
                    {
                        ex.printStackTrace();
                    }
                }
            }
        };
        handleMessages.start();


    }



    //لاستقبال الرَّقْم المراد التواصل معه
    public String receiveConnectionNumber()
    {
        try {

            System.out.print("i want  : ");
            this.connectionNumber = inputStream.readUTF() ;
            System.out.println(this.connectionNumber);
            return this.connectionNumber ;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return "";
    }

    public void sendOtherClientsNumbers(ArrayList<String> clientNumbers)
    {

        try {
            //إرسال عدد الإرقام المراد عرضها لدى المستخدم
            sendMessage(clientNumbers.size()+"");
            for(int i = 1 ; i <= clientNumbers.size() ; i++)
            {
                if (!getClientNumber().equals(clientNumbers.get(i-1)))
                    sendMessage(i+"- "+clientNumbers.get(i-1));
            }

        }catch (NullPointerException ex)
        {
            ex.printStackTrace();
        }

    }



    public void sendPublicKey(PublicKey publicKey) throws IOException {
       if(isOn){
           objectOutputStream = new ObjectOutputStream(client.getOutputStream());
           objectOutputStream.writeObject(publicKey);
       }
    }

    public SecretKey getSessionKey(PrivateKey privateKey) throws Exception {
        try {

            byte[] bytes= DatatypeConverter.parseHexBinary(inputStream.readUTF());
            String sessionAfterDecrypt =Crypto.decryptSession(bytes ,privateKey);
           byte[] data = DatatypeConverter.parseHexBinary(sessionAfterDecrypt);
           sessionKey = new SecretKeySpec(data , 0 , data.length , "AES");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sessionKey;
    }
}
