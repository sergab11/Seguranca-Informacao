//  INF1416 - Seguranca da Informacao
//  Trabalho 3
//  Felipe Ferreira (1711087) e Sergio Gabriel (1611200)

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


public class DigestCalculator {
    public static void main (String[] args) throws Exception {
        // verifiga args e recebe o texto plano
        if (args.length !=3) {
            System.err.println("Usage: java MessageDigestExample text");
            System.exit(1);
        }
        
        String tipoDigest = String.valueOf(args[0].toCharArray());
        String pathArqDigest = String.valueOf(args[1].toCharArray());
        String pathArqPlainText = String.valueOf(args[2].toCharArray()); 

        MessageDigest messageDigest = MessageDigest.getInstance(tipoDigest);
        int contArq = 0;
        File PlainTextFolder = new File(pathArqPlainText);
        File[] PlainTextArq = PlainTextFolder.listFiles();
        List<byte[]> digestsArqPlainText = new ArrayList<byte[]>();

        for (File file : PlainTextArq) {
            if (file.isFile()) {
                contArq ++;
            }
        }

        // calcula e insere os digests em uma lista
        for(int i=0; i<contArq; i++){
        	String data = "";
        	File myObj = new File(pathArqPlainText+PlainTextArq[i].getName());
        	FileReader arq = new FileReader(myObj);
        	BufferedReader myReader = new BufferedReader(arq);
        	String linha = myReader.readLine();
            while (linha != null) {
            	data += linha;
            	linha = myReader.readLine();
            }
            arq.close();
            //System.out.println(data);
            byte[] plainText = data.getBytes("UTF8");
            messageDigest.update(plainText);
            digestsArqPlainText.add(messageDigest.digest());
        }
        
        List<String> lista = new ArrayList<String>();
    	FileReader arq = new FileReader(pathArqDigest);
        BufferedReader buffRead = new BufferedReader(arq);
        String linha = buffRead.readLine();
        while (linha != null) {
        	lista.add(linha);
        	linha = buffRead.readLine();
        }
        buffRead.close();
        
        List<String> status = new ArrayList<String>();
        // comparando digest para pegar o status
        for (int i=0; i < contArq; i++) {
        	status.add("");
        	// comparando com os digests da pasta de arquivos
        	for (int j=0; j < contArq; j++) {
        		if (i != j) {
        			if (compareByteArrays(digestsArqPlainText.get(i), digestsArqPlainText.get(j))) {
        				status.set(i, "COLISION");
        			}
        		}
        	}
        	
        	// comparando com os digests da lista de digests
        	if (lista.isEmpty()) {
        		if (!status.get(i).equals("COLISION")) {
        			status.set(i, "NOT FOUND");
        		}
        	}
        	else {
        		for(int j = 0; j < lista.size(); j++) {
        			String[] linhaDiv =  lista.get(j).split(" ");
        			String nome = linhaDiv[0];
        			for (int k = 1; k < linhaDiv.length; k += 2) {
        				if (((digestHex(digestsArqPlainText.get(i))).toString()).equals(linhaDiv[k+1])) {
        					if((PlainTextArq[i].getName()).equals(nome)) {
        						status.set(i, "OK");
        						break;
        					}
        					else {
        						status.set(i, "COLISION");
        						break;
        					}
        				}
        				else {
        					if((PlainTextArq[i].getName()).equals(nome)) {
        						if (linhaDiv[k].equals(tipoDigest)) {
        							status.set(i, "NOT OK");
        							break;
        						}
        					}
        				}
        			}
        			if(!(status.get(i)).equals("")){
        				break;
        			}
        		}
        		if((status.get(i)).equals("")){
        			status.set(i, "NOT FOUND");
        		}
        	}
        	System.out.println(PlainTextArq[i].getName()+" "+tipoDigest+" "+digestHex(digestsArqPlainText.get(i))+" "+status.get(i));
        }
        
        // escrevendo na lista de digests       
        for (int i=0; i < contArq; i++) {
        	if(status.get(i).equals("NOT FOUND")) {
        		Scanner sc = new Scanner(new File(pathArqDigest));
        		StringBuffer buffer = new StringBuffer();
        		while (sc.hasNextLine()) {
        		   buffer.append(sc.nextLine()+System.lineSeparator());
        		}
        		String fileContents = buffer.toString();
        		sc.close();
        		
        		Boolean achou = false;
        		if (!lista.isEmpty()) {
	        		for (int j=0; j < lista.size(); j++) {
	        			String[] linhaDiv =  lista.get(j).split(" ");
	        			String nome = linhaDiv[0];
	        			if (nome.equals(PlainTextArq[i].getName())){
	        				achou = true;
	        				String oldLine = lista.get(j);
	        			    String newLine = lista.get(j) + " " + tipoDigest + " " + digestHex(digestsArqPlainText.get(i)).toString();
	        			    fileContents = fileContents.replaceAll(oldLine, newLine);
	        				
	        			    FileWriter writer = new FileWriter(pathArqDigest);
	        			    writer.append(fileContents);
	        			    writer.flush();
	        			    writer.close();
	        			}
	        		}
        		}
        		
        		if (achou == false){
        			
        			buffer.append(PlainTextArq[i].getName()+" "+tipoDigest+" "+digestHex(digestsArqPlainText.get(i))+System.lineSeparator());
        			fileContents = buffer.toString();
        			
        			FileWriter writer = new FileWriter(pathArqDigest);
    			    writer.append(fileContents);
    			    writer.flush();
    			    writer.close();
        		}
        	}
        }
        
    }

    public static StringBuffer digestHex(byte [] aux){
        StringBuffer buf = new StringBuffer();
        for(int k=0; k<aux.length; k++){
            String hex = Integer.toHexString(0x0100 + (aux[k] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }
        return buf;
    }

    public static boolean compareByteArrays(byte[] a1, byte[] a2){
        for(int i=0; i<a1.length; i++){
            if(a1[i] != a2[i])
                return false;
        }
        return true;
    }
}   