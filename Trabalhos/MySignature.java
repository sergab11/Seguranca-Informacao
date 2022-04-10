//  INF1416 - Segurança da Informação
//  Trabalho 2
//  Felipe Ferreira (1711087) e Sérgio Gabriel (1611200)

import java.security.*;
import javax.crypto.*;

public class MySignature {
      String signPattern = "";
      PrivateKey priv;
      PublicKey pub;
      byte [] text;

      public void getInstance(String pattern){
        String aux = "";
        for(int i=0; i<pattern.indexOf("w"); i++)
          aux += pattern.charAt(i);

        if(aux.charAt(0) == 'M')
          this.signPattern = aux;
        else{
          this.signPattern+="SHA-";
          for(int i=3; i<aux.length(); i++)
            this.signPattern+=aux.charAt(i);
        }
      }

      public void initSign(PrivateKey key){
        this.priv = key;
      }

      public void update(byte[] plainTexString){
        this.text = plainTexString.clone();
      }

      public byte[] sign() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        MessageDigest msgD = MessageDigest.getInstance(this.signPattern);
        msgD.update(this.text);
        byte [] digest = msgD.digest();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.priv);
        byte [] cipherDigest = cipher.doFinal(digest);

        return cipherDigest;
      }

      public void initVerify(PublicKey key){
        this.pub = key;
      }

      public boolean verify(byte [] signature) throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException{
        MessageDigest msgD = MessageDigest.getInstance(this.signPattern);
        msgD.update(this.text);
        byte [] originalDigest = msgD.digest();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.pub);
        byte [] newDigest = cipher.doFinal(signature);

        for(int i=0; i<originalDigest.length; i++){
          if(originalDigest[i] != newDigest[i])
            return false;
        }

        return true;
      }
}
