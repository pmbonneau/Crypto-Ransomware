package ransomware;

import java.util.Base64; 
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
 
public class sampleAES {
 
 
 /*Fonction de chiffrement : elle prend le message à chiffrer, la clé et iv et elle retourne le message chiffré en base64*/
    public static String encrypt(String strToEncrypt, SecretKey key, IvParameterSpec iv) 
    {
        try
        {
           //créer une instance d'un algorithme AES avec un mode CBC et un padding de type PKCS5
           Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                  
           //initialier la clé, iv et indiquer qu'il s'agit d'un chifrement 
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
  
            //chiffrer le message
            byte[] encrypted =cipher.doFinal(strToEncrypt.getBytes("UTF-8"));

           //encoder le résultat en base64
            String encryptedBase64=Base64.getEncoder().encodeToString(encrypted);
            return encryptedBase64;
        }
        catch (Exception e)
        {   //en cas d'erreur, afficher un message et retourner la chaine nulle comme résultat
            System.out.println("Error while encrypting: " + e.toString());
            return null;
        }
        
    }


/*Fonction de déchiffrement : elle prend le message à déchiffrer en base64, la clé et iv et elle retourne le message clair correspondant*/
 
    public static String decrypt(String strToDecrypt, SecretKey key, IvParameterSpec iv)
    {
        try
        { 
            //créer une instance d'un algorithme AES avec un mode CBC et un padding de type PKCS5
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            //initialier la clé, iv et indiquer qu'il s'agit d'un déchifrement 
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
          
          //Décoder le message chiffré de sa forme base64
          byte[] encryptedBytes = Base64.getDecoder().decode(strToDecrypt);    
         
          //déchifrer le message
          byte[] original = cipher.doFinal(encryptedBytes);
          return new String(original);
        }
        catch (Exception e)
        {   //en cas d'erreur, afficher un message et retourner la chaine nulle comme résultat
            System.out.println("Error while decrypting: " + e.toString());
            return null;
        }
  
    }
    
    public static void AES()
    {
        String originalString="Hello world";
        
        try{
            //créer une instance d'un générateur de clés AES
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");               
            //initialiser la taille de la clé
            keyGen.init(128); 
             //générer aléatoirement une clé AES de 128 bits
            SecretKey key = keyGen.generateKey();

            //Créer une instance d'un générateur aléatoire sécuritaire
            SecureRandom random = new SecureRandom();
            //générer iv aléatoirement de 16 octes
            byte[] iv0 = random.generateSeed(16);
            IvParameterSpec iv = new IvParameterSpec(iv0);

            String encryptedString = sampleAES.encrypt(originalString, key, iv) ;


            String decryptedString = sampleAES.decrypt(encryptedString, key, iv) ;

            System.out.println("origianal String : " + originalString);
            System.out.println("encrypted String en base64: " + encryptedString);
            System.out.println("decrypted String :" + decryptedString);
            }
             catch(Exception ex)
             {
                System.out.println(ex.getMessage());
             }
	}
}

