//  INF1416 - Seguranca da Informacao
//  Trabalho 4
//  Felipe Ferreira (1711087) e Sergio Gabriel (1611200)

import java.io.BufferedInputStream; import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File; import java.io.FileInputStream; import java.io.FileOutputStream;
import java.io.Console;
import java.io.FileNotFoundException; import java.io.FileReader;
import java.io.IOException; import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException; import java.security.KeyFactory;
import java.security.MessageDigest; import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey; import java.security.PublicKey;
import java.security.SecureRandom; import java.security.Signature;
import java.security.SignatureException; import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.spec.EncodedKeySpec; import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection; import java.util.ArrayList;
import java.util.Arrays; import java.util.Base64;
import java.util.Collection; import java.util.Date;
import java.util.Iterator; import java.util.List;
import java.util.Random; import java.util.Scanner;
import java.sql.Timestamp;
import javax.crypto.BadPaddingException; import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException; import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException; import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;



public class DigitalVault {
	//static String PATH = ".";
	static String PATH = "C:\\Users\\DELL\\Documents\\CCP\\Seg-Info\\Trabalhos\\T4\\Pacote-T4";
	
	static int numUsuarios = 0;
	static int stage = 1;
	public static Scanner myObj = new Scanner(System.in);
	public static void main (String[] args) throws Exception {
		DigitalVaultDB DB = new DigitalVaultDB("banco3");
		DB.createTables();
		sqliteStartTables(DB);
		numUsuarios = DB.getNumUsers();
		int id = Autentication(DB);
		UserInteraction(DB, id);
	}
	
    public static void sqliteStartTables(DigitalVaultDB DB) {
    	int size = DB.getSizeTable("GRUPOS");
    	if (size == 0) {
    		DB.startGrupos();
    	}
    	size = DB.getNumUsers();
    	//System.out.println(size);
    	if (size == 0) {
    		registerNewUser(PATH+"\\Keys\\admin-x509.crt", "0123456789", "Administrador", DB);
    	}
		size = DB.getSizeTable("MENSAGENS");
    	if (size == 0) {
    		DB.startMensagens();
    	}
    }
	
	public static int Autentication(DigitalVaultDB DB) {
		long now = System.currentTimeMillis();
        Timestamp data = new Timestamp(now);
		DB.insertRegisterInDB(data, 1001, "", "");
		boolean autenticado = false;
		int etapa = 0;
		int id = -1;
		while (!autenticado) {
			if (etapa == 0) {
				etapa = firstStage(DB); // retorna id caso exista e nao esteja bloqueado
				if (etapa != -1) {
					id = etapa;
					etapa = 1;
				}
				else {
					etapa = 0;
				}
			}
			else if (etapa == 1) {
				etapa = secondStage(DB, id);
			}
			else if (etapa == 2) {
				etapa = thirdStage(DB, id);
				if (etapa == 3) {
					autenticado = true;
				}
			}
		}
		return id;
	}

	// representa a primeira etapa da autenticação bifator
	public static int firstStage(DigitalVaultDB DB){
		long now = System.currentTimeMillis();
		Timestamp data = new Timestamp(now);
		DB.insertRegisterInDB(data, 2001, "", "");
		System.out.println("\nCofre Digital - Autenticacao\nLogin name: ");
		String givenEmail = myObj.nextLine();  // Read user input
		System.out.println("_____OK_____|___LIMPAR___");
		String givenOption = myObj.nextLine();
		if(givenOption.equals("OK")){
			int s = DB.searchEmail(givenEmail);
			if(s != 0){
				if(DB.verifyBlocked(s)){
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					DB.insertRegisterInDB(data, 2004, givenEmail, "");
					System.out.println("Usuario " + givenEmail + " se encontra bloqueado!\n");
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					DB.insertRegisterInDB(data, 2002, "", "");
					return -1;
				}
				else
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					DB.insertRegisterInDB(data, 2003, givenEmail, "");
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					DB.insertRegisterInDB(data, 2002, "", "");
					return s;
			}
			else{
				now = System.currentTimeMillis();
				data = new Timestamp(now);
				DB.insertRegisterInDB(data, 2005, givenEmail, "");
				System.out.println("Login invalido!");
			}
		}
		now = System.currentTimeMillis();
		data = new Timestamp(now);
		DB.insertRegisterInDB(data, 2002, "", "");
		return -1;
	}
	
	public static int secondStage(DigitalVaultDB db, int user_id){
		long now = System.currentTimeMillis();
		Timestamp data = new Timestamp(now);
		db.insertRegisterInDB(data, 3001, db.getUserEmail(user_id), "");
		List<int[]> given_pass = new ArrayList<int[]>();
		given_pass = AskPassword();
		if(compareFullPassword(user_id, given_pass, db)){
			now = System.currentTimeMillis();
			data = new Timestamp(now);
			db.insertRegisterInDB(data, 3003, db.getUserEmail(user_id), "");
			db.zeroUserCounter(user_id);
			now = System.currentTimeMillis();
			data = new Timestamp(now);
			db.insertRegisterInDB(data, 3002, db.getUserEmail(user_id), "");
			return 2;
		}
		else {
			int CT = db.incUserCounter(user_id);
			if(CT == 0){
				now = System.currentTimeMillis();
				data = new Timestamp(now);
				db.insertRegisterInDB(data, 3006, db.getUserEmail(user_id), "");
				now = System.currentTimeMillis();
				data = new Timestamp(now);
				db.insertRegisterInDB(data, 3007, db.getUserEmail(user_id), "");
				System.out.println("Tres tentativas mal sucedidas. Usuario bloqueado!\n");
				now = System.currentTimeMillis();
				data = new Timestamp(now);
				db.insertRegisterInDB(data, 3002, db.getUserEmail(user_id), "");
				return 0;
			}
			else{
				if (CT == 1){
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 3004, db.getUserEmail(user_id), "");
				}
				else {
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 3005, db.getUserEmail(user_id), "");
				}
				System.out.println(CT+" tentativa(s) mal sucedidas!\n");
				return 1;
			}
		}
	}

	public static int thirdStage(DigitalVaultDB db, int user_id){
		long now = System.currentTimeMillis();
		Timestamp data = new Timestamp(now);
		db.insertRegisterInDB(data, 4001, db.getUserEmail(user_id), "");
		System.out.println("\nCofre Digital - Autenticacao\n");
		System.out.println("Endereco da chave privada: ");
		String endereco = myObj.nextLine();  // Read user input
		System.out.println("Endereco da chave privada: "+endereco);
		Console console = System.console() ;
		String givenSecretPhrase = new String(console.readPassword("Frase secreta: "));
		//String givenSecretPhrase = myObj.nextLine();
		System.out.println("Endereco da chave privada: "+endereco+"\nFrase secreta:"+"*".repeat(givenSecretPhrase.length()));
		System.out.println("_____OK_____|___LIMPAR___");
		String givenOption = myObj.nextLine();
		
		if(givenOption.equals("OK")){
			String tipo_arq = endereco.substring(endereco.length() - 3);
			if(tipo_arq.equals("key") == false){
				System.out.println("Endereco fornecido invalido!\n");
				return 2;
			}

			if(privateKeyValidation(givenSecretPhrase, endereco, user_id, db)){
				now = System.currentTimeMillis();
				data = new Timestamp(now);
				db.insertRegisterInDB(data, 4003, db.getUserEmail(user_id), "");
				System.out.println("3a fase de validacao concluida!\n");
				db.zeroUserCounter(user_id);
				db.incUserAcess(user_id);
				now = System.currentTimeMillis();
				data = new Timestamp(now);
				db.insertRegisterInDB(data, 4002, db.getUserEmail(user_id), "");
				return 3;
			}
			else{
				int CT = db.incUserCounter(user_id);
				if(CT == 0){
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 4007, db.getUserEmail(user_id), "");
					System.out.println("Tres tentativas mal sucedidas. Usuario bloqueado!\n");
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 4002, db.getUserEmail(user_id), "");
					return 0;
				}
				else{
					System.out.println(CT+" tentativa(s) mal sucedidas!\n");
					return 2;
				}
			}
		}
		return 2;
	}
	
	public static void UserInteraction(DigitalVaultDB db, int user_id) {
		int comando = 0;
		while (comando != 5) {
			comando = Corpo2(db, user_id, comando);
		}
	}
	
	public static void Cabecalho(DigitalVaultDB db, int user_id) {
		String email = db.getUserEmail(user_id);
		String grupo = db.getUserGrupo(user_id);
		String nome = email.substring(0, email.indexOf("@"));
		System.out.println("\n\n\n\n");
		System.out.println("Login: "+email);
		System.out.println("Grupo: "+grupo);
		System.out.println("Nome: "+nome);
	}
	
	public static void Corpo1(DigitalVaultDB db, int user_id, int comando) {
		int cnt = -1;
		if (comando == 1) {
			cnt = db.getNumUsers();
			System.out.println("\nTotal de usuarios do sistema: "+cnt);
		}
		else if (comando == 3) {
			cnt = db.getUserConsultas(user_id);
			System.out.println("\nTotal de consultas do usuario: "+cnt);
		}
		else {
			cnt = db.getUserAcessos(user_id);
			System.out.println("\nTotal de acessos do usuario: "+cnt);
		}
	}
	
	public static int Corpo2(DigitalVaultDB db, int user_id, int comando) {
		int next_comando = 0;
		String command = null;
		long now = System.currentTimeMillis();;
		if (comando == 0) {
			now = System.currentTimeMillis();
			Timestamp data = new Timestamp(now);
			db.insertRegisterInDB(data, 5001, db.getUserEmail(user_id), "");
			Cabecalho(db, user_id);
			Corpo1(db, user_id, comando);
			String grupo = db.getUserGrupo(user_id);
			if (grupo.equals("Administrador")) {
				System.out.println("\nMenu Principal:\n");
				System.out.println("1 - Cadastrar um novo usuario");
				System.out.println("2 - Alterar senha pessoal e certificado digital do usuario");
				System.out.println("3 - Consultar pasta de arquivos secretos do usuario");
				System.out.println("4 - Sair do Sistema");
				command = myObj.nextLine();
				while (Integer.parseInt(command) < 1 || Integer.parseInt(command) > 4) {
					System.out.println("COMANDO INVALIDO!");
					command = myObj.nextLine();
				}
				if ( command.equals("1")){
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 5002, db.getUserEmail(user_id), "");
				}
				else if (command.equals("2")) {
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 5003, db.getUserEmail(user_id), "");
				}
				else if (command.equals("3")) {
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 5004, db.getUserEmail(user_id), "");
				}
				else if (command.equals("4")) {
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 5005, db.getUserEmail(user_id), "");
				}
			}
			else {
				System.out.println("\nMenu Principal:\n");
				System.out.println("1 - Alterar senha pessoal e certificado digital do usuario");
				System.out.println("2 - Consultar pasta de arquivos secretos do usuario");
				System.out.println("3 - Sair do Sistema");
				command = myObj.nextLine();
				while (Integer.parseInt(command) < 1 || Integer.parseInt(command) > 3) {
					System.out.println("COMANDO INVALIDO!");
					command = myObj.nextLine();
				}
				command = Integer.toString(Integer.parseInt(command)+1);
				if ( command.equals("2")){
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 5002, db.getUserEmail(user_id), "");
				}
				else if (command.equals("3")) {
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 5003, db.getUserEmail(user_id), "");
				}
				else if (command.equals("4")) {
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 5004, db.getUserEmail(user_id), "");
				}
			}
		}
		else if (comando == 1) {
			now = System.currentTimeMillis();
			Timestamp data = new Timestamp(now);
			db.insertRegisterInDB(data, 6001, db.getUserEmail(user_id), "");
			int i = 0;
			String caminho = null;
			String grupo = null;
			String senha = null;
			String conf = null;
			while (i < 5) {
				Cabecalho(db, user_id);
				Corpo1(db, user_id, comando);
				System.out.println("\nFormulario de Cadastro:\n");
				if (i == 0) {
					System.out.print("- Caminho do arquivo do certificado digital: \n"
									+ "0 - Voltar para o Menu Principal\n"
									+ "Caminho: \n");
					caminho = myObj.nextLine();
					if (!hasLetter(caminho)) {
						if (Integer.parseInt(caminho) == 0) {
							command = caminho;
							break;
						}
					}
					else {
						i++;
					}
				}
				else if (i == 1) {
					System.out.print("- Caminho do arquivo do certificado digital: "+caminho+"\n"
									+ "- Grupo: Administrador ou Usuario\n"
									+ "0 - Voltar para o Menu Principal\n"
									+ "Grupo: \n");
					grupo = myObj.nextLine();
					if (!hasLetter(grupo)) {
						if (Integer.parseInt(grupo) == 0) {
							command = grupo;
							break;
						}
					}
					else {
						if (grupo.equals("Administrador") || grupo.equals("Usuario")) {
							i++;
						}
					}
				}
				else if (i == 2) {
					System.out.print("- Caminho do arquivo do certificado digital: "+caminho+"\n"
									+ "- Grupo: "+grupo+"\n"
									+ "- Senha pessoal: Apenas numeros e entre 8 e 10 caracteres\n"
									+ "0 - Voltar para o Menu Principal\n");
					Console console = System.console() ;
					senha = new String(console.readPassword("Senha Pessoal: "));
					//senha = myObj.nextLine();
					if (!hasLetter(senha)) {
						if (Integer.parseInt(senha) == 0) {
							command = senha;
							break;
						}
						else {
							if ( senha.length() >= 8 &&  senha.length() <= 10 && !hasRep(senha)) {
								i++;
							}
							else {
								now = System.currentTimeMillis();
								data = new Timestamp(now);
								db.insertRegisterInDB(data, 6003, db.getUserEmail(user_id), "");
							}
						}
					}
				}
				else if (i == 3) {
					System.out.print("- Caminho do arquivo do certificado digital: "+caminho+"\n"
									+ "- Grupo: "+grupo+"\n"
									+ "- Senha pessoal: "+"*".repeat(senha.length())+"\n"
									+ "- Confirmacao senha pessoal: \n"
									+ "0 - Voltar para o Menu Principal\n");
					Console console = System.console() ;
					conf = new String(console.readPassword("Confirmacao: "));
					//conf = myObj.nextLine();
					if (!hasLetter(conf)) {
						if (Integer.parseInt(conf) == 0) {
							command = conf;
							break;
						}
						else {
							if ( senha.equals(conf) ) {
								i++;
							}
						}
					}
				}
				else if (i == 4) {
					System.out.print("- Caminho do arquivo do certificado digital: "+caminho+"\n"
									+ "- Grupo: "+grupo+"\n"
									+ "- Senha pessoal: "+"*".repeat(senha.length())+"\n"
									+ "- Confirmacao senha pessoal: "+"*".repeat(conf.length())+"\n"
									+ "0 - Voltar para o Menu Principal\n"
									+ "1 - Cadastrar\n");
					command = myObj.nextLine();
					if (!hasLetter(command)) {
						if (Integer.parseInt(command) == 0) {
							break;
						}
						else if (Integer.parseInt(command) == 1){
							try{
							now = System.currentTimeMillis();
							data = new Timestamp(now);
							db.insertRegisterInDB(data, 6002, db.getUserEmail(user_id), "");
							FileInputStream fis = new FileInputStream(caminho);
							CertificateFactory cf = CertificateFactory.getInstance("X.509");
							X509Certificate CERT = (X509Certificate)cf.generateCertificate(fis);
							
							int ver = CERT.getVersion();
							BigInteger serie = CERT.getSerialNumber();
							Date validade = CERT.getNotAfter();
							String assinatura = CERT.getSigAlgName();
							X500Principal issuer = CERT.getIssuerX500Principal();
							X500Principal subject = CERT.getSubjectX500Principal();
							
							Cabecalho(db, user_id);
							Corpo1(db, user_id, comando);
							System.out.println("\nFormulario de Cadastro:\n");
							System.out.print("- Caminho do arquivo do certificado digital: "+caminho+"\n"
											+ "- Grupo: "+grupo+"\n"
											+ "- Senha pessoal: "+"*".repeat(senha.length())+"\n"
											+ "- Confirmacao senha pessoal: "+"*".repeat(conf.length())+"\n"
											+ "CERTIFICADO:\n"
											+ "Versao: " + Integer.toString(ver) +"\n"
											+ "Serie: " + serie.toString() +"\n"
											+ "Validade: " + validade.toString() +"\n"
											+ "Assinatura: " + assinatura +"\n"
											+ "Emissor: " + issuer.toString() +"\n"
											+ "Sujeito: " + subject.toString() +"\n"
											+ "0 - Voltar para o Menu Principal\n"
											+ "1 - Confirmar\n");
									command = myObj.nextLine();
									while (!command.equals("0") && !command.equals("1")) {
										System.out.println("COMANDO INVALIDO!");
										command = myObj.nextLine();
									}
									if (Integer.parseInt(command) == 0) {
										now = System.currentTimeMillis();
										data = new Timestamp(now);
										db.insertRegisterInDB(data, 6006, db.getUserEmail(user_id), "");
										break;
									}
									else {
										now = System.currentTimeMillis();
										data = new Timestamp(now);
										db.insertRegisterInDB(data, 6005, db.getUserEmail(user_id), "");
										registerNewUser(caminho, senha, grupo, db);
										command = "0";
										i++;
									}
							} 	catch(CertificateEncodingException E1){System.out.println("Encoding");}
								catch(FileNotFoundException E2){
									System.out.println("FILE NOT FOUND");
									now = System.currentTimeMillis();
									data = new Timestamp(now);
									db.insertRegisterInDB(data, 6004, db.getUserEmail(user_id), "");
								}
								catch(CertificateException E3){System.out.println("Cert");}
						}
					}
				}
			}
		}
		else if (comando == 2) {
			now = System.currentTimeMillis();
			Timestamp data = new Timestamp(now);
			db.insertRegisterInDB(data, 7001, db.getUserEmail(user_id), "");
			int i = 0;
			String caminho = null;
			String senha = null;
			String conf = null;
			while (i < 3) {
				Cabecalho(db, user_id);
				Corpo1(db, user_id, comando);
				System.out.println("\nAlterar Cadastro:\n");
				if (i == 0) {
					System.out.print("- Caminho do arquivo do certificado digital: \n"
									+ "0 - Voltar para o Menu Principal\n"
									+ "Caminho: \n");
					caminho = myObj.nextLine();
					if (!hasLetter(caminho)) {
						if (Integer.parseInt(caminho) == 0) {
							command = caminho;
							break;
						}
					}
					else{
						i++;
					}
				}
				else if (i == 1) {
					System.out.print("- Caminho do arquivo do certificado digital: "+caminho+"\n"
									+ "- Senha pessoal: Apenas numeros e entre 8 e 10 caracteres\n"
									+ "0 - Voltar para o Menu Principal\n");
					Console console = System.console() ;
					senha = new String(console.readPassword("Senha: "));
					//senha = myObj.nextLine();
					if (senha.equals("")){
						i++;
					}
					//if (senha.equals(""))
						//break;
					else if (!hasLetter(senha)) {
						if (Integer.parseInt(senha) == 0) {
							command = senha;
							break;
						}
						else {
							if ( senha.length() >= 8 && senha.length() <= 10 && !hasRep(senha)) {
								i++;
							}
							else {
								now = System.currentTimeMillis();
								data = new Timestamp(now);
								db.insertRegisterInDB(data, 7002, db.getUserEmail(user_id), "");
							}
						}
					}
				}
				else if (i == 2) {
					System.out.print("- Caminho do arquivo do certificado digital: "+caminho+"\n"
									+ "- Senha pessoal: "+"*".repeat(senha.length())+"\n"
									+ "- Confirmacao senha pessoal: \n"
									+ "0 - Voltar para o Menu Principal\n");
					Console console = System.console() ;
					conf = new String(console.readPassword("Confirmacao: "));
					//conf = myObj.nextLine();
					if ( senha.equals(conf) ) {
						i++;
						if (!caminho.equals("")) {
							changeCert(user_id, caminho, db);
						}
						if (!senha.equals("")) {
							changePassword(user_id, senha, db);
						}
						now = System.currentTimeMillis();
						data = new Timestamp(now);
						db.insertRegisterInDB(data, 7004, db.getUserEmail(user_id), "");
						command = "0";
					}
					if (!hasLetter(conf)) {
						if (Integer.parseInt(conf) == 0) {
							command = conf;
							break;
						}
					}
				}
			}
		}
		else if (comando == 3) {
			now = System.currentTimeMillis();
			Timestamp data = new Timestamp(now);
			db.insertRegisterInDB(data, 8001, db.getUserEmail(user_id), "");
			String caminho = null;
			Cabecalho(db, user_id);
			Corpo1(db, user_id, comando);
			System.out.println("\nPagina de Arquivos:\n");
			System.out.println("Caminho da pasta: ");
			System.out.println("0 - Voltar ao Menu Principal");
			System.out.println("Caminho: (Sem barra no final)");
			caminho = myObj.nextLine();
			if (!hasLetter(caminho)) {
				if (Integer.parseInt(caminho) == 0) {
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 8002, db.getUserEmail(user_id), "");
					command = caminho;
				}
			}
			else {
				System.out.println("1 - Listar");
				command = myObj.nextLine();
				if (!hasLetter(command)) {
					if (Integer.parseInt(command) == 1) {
						now = System.currentTimeMillis();
						data = new Timestamp(now);
						db.insertRegisterInDB(data, 8003, db.getUserEmail(user_id), "");
						String email = db.getUserEmail(user_id);
						String nome = email.substring(0, email.indexOf("@"));
								
						SecretKey key = get_KDES(nome);
						//System.out.println(caminho.substring(0, caminho.length()-5)+"Keys/"+nome+"-pkcs8-des.key");
						byte[] pk_64 = decrypt_DES(key, caminho.substring(0, caminho.length()-5)+"Keys/"+nome+"-pkcs8-des.key");
						byte[] pkcs8EncodedKey = decoder_pk(pk_64);
						EncodedKeySpec privateKeySpec = Encoded(pkcs8EncodedKey);
						PrivateKey pk = keyfactory(privateKeySpec);
						PublicKey pubkey = get_public_DB(user_id, db);

						Cabecalho(db, user_id);
						Corpo1(db, user_id, comando);
						System.out.println("\nPagina de Arquivos:\n");
						System.out.println("Caminho da pasta: " + caminho);
						//System.out.println("0 - Voltar ao Menu Principal");
						String[] decod = showIndex(db, user_id, caminho, pk, pubkey);
						db.incUserConsultas(user_id);
						
						/*
						Cabecalho(db, user_id);
						Corpo1(db, user_id, comando);
						System.out.println("\nPagina de Arquivos:\n");
						System.out.println("Caminho da pasta: " + caminho+"\n");
						*/
						
						//protectedFileValidation(db, user_id, caminho, "index", pk, pubkey);
						
						now = System.currentTimeMillis();
						data = new Timestamp(now);
						db.insertRegisterInDB(data, 8009, db.getUserEmail(user_id), "");
						System.out.println("0 - Voltar ao Menu Principal");
						System.out.println("Nome secreto do arquivo - Descriptografar arquivo");
						command = myObj.nextLine();
						if (!hasLetter(command)) {
							if (Integer.parseInt(command) != 0) {
								command = "3";
							}
						}
						else {
							System.out.println("DRESCRIPTOGRAFANDO...");
							for(int i = 0; i < decod.length; i++){
								if (command.equals(decod[i])) {
									now = System.currentTimeMillis();
									data = new Timestamp(now);
									db.insertRegisterInDB(data, 8010, db.getUserEmail(user_id), decod[i-1]);
									protectedFileValidation(db, user_id, caminho, decod[i-1], pk, pubkey);
								}
							}
							command = "3";
						}
					}
					else if (Integer.parseInt(command) != 0) {
						command = "3";
					}
				}
				else {
					command = "3";
				}
			}
		}
		else if (comando == 4) {
			now = System.currentTimeMillis();
			Timestamp data = new Timestamp(now);
			db.insertRegisterInDB(data, 9001, db.getUserEmail(user_id), "");
			Cabecalho(db, user_id);
			Corpo1(db, user_id, comando);
			System.out.println("\nSaida do sistema:\n");
			System.out.println("Pressione o botao Sair para confirmar\n");
			System.out.println("1 - Sair");
			System.out.println("2 - Voltar ao Menu Principal");
			command = myObj.nextLine();
			while (Integer.parseInt(command) < 1 || Integer.parseInt(command) > 2) {
				System.out.println("COMANDO INVALIDO!");
				command = myObj.nextLine();
			}
			if (command.equals("1")) {
				now = System.currentTimeMillis();
				data = new Timestamp(now);
				db.insertRegisterInDB(data, 9003, db.getUserEmail(user_id), "");
				now = System.currentTimeMillis();
				data = new Timestamp(now);
				db.insertRegisterInDB(data, 1002, "", "");
				command = "5";
			}
			else {
				now = System.currentTimeMillis();
				data = new Timestamp(now);
				db.insertRegisterInDB(data, 9004, db.getUserEmail(user_id), "");
				command = "0";
			}
		}
		//myObj.close();
		next_comando = Integer.parseInt(command);
		return next_comando;
	}
	
	public static boolean hasLetter(String texto) {
		String numeros = "0123456789";
		boolean letra = false;
		for (int j = 0; j < texto.length(); j++) {
			if (numeros.indexOf(texto.charAt(j)) == -1){
				letra = true;
				break;
			}
		}
		return letra;
	}
	
	public static boolean hasRep(String texto) {
		boolean rep = false;
		for (int i = 1; i < texto.length(); i++) {
			if (texto.charAt(i) == texto.charAt(i-1)){
				rep = true;
				break;
			}
		}
		return rep;
	}

	public static boolean privateKeyValidation(String frase, String end, int user_id, DigitalVaultDB db){
		SecretKey givenSK = get_KDES(frase);

		File file = new File(end);
		boolean exists = file.exists();
		if(exists == false){
			long now = System.currentTimeMillis();
			Timestamp data = new Timestamp(now);
			db.insertRegisterInDB(data, 4004, db.getUserEmail(user_id), "");
			System.out.println("Endereco nao foi escrito da forma correta ou nao existe!");
			return false;
		}

		byte[] pk_64 = decrypt_DES(givenSK, end);
		if (pk_64 != null){
			byte[] pkcs8EncodedKey = decoder_pk(pk_64);

			EncodedKeySpec privateKeySpec = Encoded(pkcs8EncodedKey);

			PrivateKey given_pk = keyfactory(privateKeySpec);
			PublicKey pubkey = get_public_DB(user_id, db);
			boolean verify = verify_sig(given_pk, pubkey);
			if (!verify) {
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 4006, db.getUserEmail(user_id), "");
			}
			return verify;
		}
		else {
			long now = System.currentTimeMillis();
			Timestamp data = new Timestamp(now);
			db.insertRegisterInDB(data, 4005, db.getUserEmail(user_id), "");
			System.out.println("FRASE SECRETA INVALIDA");
			return false;
		}
	}
	
	// recebe uma frase secreta, torna-a uma semente, gera uma chave secreta e retorna-a 
	public static SecretKey get_KDES(String frase) { 
		byte[] keyStart = frase.getBytes();
		try{
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			sr.setSeed(keyStart); // Define seed a partir da frase secreta
			KeyGenerator kgen = KeyGenerator.getInstance("DES");
			kgen.init(56, sr);
			SecretKey key = kgen.generateKey(); // recupera chave simetrica
			//print_KEY(key);
			return key;
		} catch(NoSuchAlgorithmException E){
		}
		return null;
	}
	
	// recebe uma chave secreta e o nome do usuário que terá sua chave privada retornada em base64 pela função 
	public static byte[] decrypt_DES(SecretKey key, String end) {
		try{
			Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
			decrypt.init(Cipher.DECRYPT_MODE, key);
			
			FileInputStream fis = new FileInputStream(end);
			byte[] data = fis.readAllBytes();
			fis.close();
			
			byte[] pk_64 = decrypt.doFinal(data);
			return pk_64;
		} catch(NoSuchAlgorithmException E1){}
		catch(NoSuchPaddingException E2){}
		catch(InvalidKeyException E3){}
		catch(IOException E4){}
		catch(IllegalBlockSizeException E5){}
		catch(BadPaddingException E6){}

		return null;
	}
	
	// recebe uma chave privada em base64 e retorna-a em binário (ASCII)
	public static byte[] decoder_pk(byte[] pk_64) {
		final String PEM_PRIVATE_START = "-----BEGIN PRIVATE KEY-----";
        final String PEM_PRIVATE_END = "-----END PRIVATE KEY-----";
        
        String privateKeyPem = new String(pk_64);
		
		privateKeyPem = privateKeyPem.replace(PEM_PRIVATE_START, "").replace(PEM_PRIVATE_END, "");
        privateKeyPem = privateKeyPem.replaceAll("\\s", "");

        byte[] pkcs8EncodedKey = Base64.getDecoder().decode(privateKeyPem);

        return pkcs8EncodedKey;
	}
	
	// recebe uma chave privada em PKCS8 e retorna em EncodedKeySpec
	public static EncodedKeySpec Encoded(byte[] pkcs8EncodedKey) {
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pkcs8EncodedKey);
		return privateKeySpec;
	}
	
	// recebe um objeto EncodedKeySpec e passa para objeto PrivateKey
	public static PrivateKey keyfactory(EncodedKeySpec privateKeySpec){
		try{
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			//System.out.println("Chave privada: " + privateKey);
			return privateKey;
		} catch(NoSuchAlgorithmException E1){}
		catch(InvalidKeySpecException E2){}

		return null;
	}
	
	// recece o nome do usuário que cujo certificado será retornado pela função
	public static Certificate get_cert(String user_name){
		try{
			FileInputStream fis = new FileInputStream(PATH+"\\Keys\\"+user_name+"-x509.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Certificate cert = cf.generateCertificate(fis);
			return cert;
		} catch(FileNotFoundException E1){
			System.out.println("Problema na leitura do arquivo!");
		}
		catch(CertificateException E2){}

		return null;
	}
	
	// recebe um certificado e retorna a chave pública contida nele
	public static PublicKey get_public(Certificate cert) {
		PublicKey publickey = cert.getPublicKey();
		return publickey;
	}
	
	// verifica a assinatura digital através da criação de um array aleatório de 2048, assinando-o com a chave privada, decriptando-o com a chave pública e verificando se o conteúdo do array aleatório é o mesmo  após a decriptação
	public static boolean verify_sig(PrivateKey pk, PublicKey pubkey)  {	
		String rand = getAlphaNumericString(2048);
		
		try{
			Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initSign(pk);
			sig.update(rand.getBytes("UTF8"));
			byte[] signature = sig.sign();

			// converte o signature para hexadecimal
			StringBuffer buf = new StringBuffer();
			for(int i = 0; i < signature.length; i++) {
				String hex = Integer.toHexString(0x0100 + (signature[i] & 0x00FF)).substring(1);
				buf.append((hex.length() < 2 ? "0" : "") + hex);
			}
			
			System.out.println( "\nStart signature verification" );
			sig.initVerify(pubkey);
			sig.update(rand.getBytes("UTF8"));
			return sig.verify(signature);
		} catch(NoSuchAlgorithmException E1){}
		catch(InvalidKeyException E2){}
		catch(UnsupportedEncodingException E3){}
		catch(SignatureException E4){}

		return false;
	}
	
	// recebe o tamanho do array que será composto de caracteres aleatorios e retorna-o
	public static String getAlphaNumericString(int n) {
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    + "0123456789"
                                    + "abcdefghijklmnopqrstuvxyz";
  
        StringBuilder sb = new StringBuilder(n);
  
        for (int i = 0; i < n; i++) {
            int index
                = (int)(AlphaNumericString.length()
                        * Math.random());
  
            sb.append(AlphaNumericString
                          .charAt(index));
        }
        return sb.toString();
    }
	
	public static void print_KEY(SecretKey key) {
		String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
		System.out.println("KDES: "+encodedKey);
	}

	// recebe o nome do usuário que deseja ter acesso ao criptograma decifrado e a chave secreta do arquivo em questão e retorna o conteúdo do arquivo cifrado
	public static byte [] decryptCryptogram (DigitalVaultDB db, int user_id, String path, String name, SecretKey kdes) {
		try{
			FileInputStream arq = new FileInputStream(path+name+".enc");
			byte[] cont_enc = arq.readAllBytes();
			arq.close();

			Cipher decrypt_enc = Cipher.getInstance("DES/ECB/PKCS5Padding");
			decrypt_enc.init(Cipher.DECRYPT_MODE, kdes);
			byte[] conteudo = decrypt_enc.doFinal(cont_enc);
			if (name.equals("index")){
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 8005, db.getUserEmail(user_id), "");
			}
			else {
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 8013, db.getUserEmail(user_id), name);
			}
			return conteudo;
		} catch(IOException E1){}
		catch(NoSuchAlgorithmException E2){}
		catch(InvalidKeyException E3){}
		catch(IllegalBlockSizeException E4){
			if (name.equals("index")){
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 8007, db.getUserEmail(user_id), "");
			}
			else {
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 8015, db.getUserEmail(user_id), name);
			}
		}
		catch(NoSuchPaddingException E5){
			if (name.equals("index")){
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 8007, db.getUserEmail(user_id), "");
			}
			else {
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 8015, db.getUserEmail(user_id), name);
			}
		}
		catch(BadPaddingException E6){
			if (name.equals("index")){
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 8007, db.getUserEmail(user_id), "");
			}
			else {
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 8015, db.getUserEmail(user_id), name);
			}
		}

		return null;
	}

	public static String[] showIndex(DigitalVaultDB db, int user_id, String path, PrivateKey kpriv, PublicKey user_Kpub){
		try{
			String[] textoSeparado = null;
			String file_name = "index";
			//System.out.println(path+"/"+file_name+".env");
			FileInputStream arq = new FileInputStream(path+"/"+file_name+".env");
			byte[] content_env = arq.readAllBytes();
			arq.close();

			Cipher decrypt_env = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			System.out.println( "\nStart digital envelope decryption" );
			decrypt_env.init(Cipher.DECRYPT_MODE, kpriv);
			byte[] seed = decrypt_env.doFinal(content_env);

			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			sr.setSeed(seed); // Define seed a partir da decriptação do envelope
			KeyGenerator kgen = KeyGenerator.getInstance("DES");
			kgen.init(56, sr);
			SecretKey KDES = kgen.generateKey(); // recupera chave simetrica
			
			System.out.println( "\nStart cryptogram decryption" );
			byte[] conteudo = decryptCryptogram(db, user_id, path+"/", file_name, KDES);

			FileInputStream arq2 = new FileInputStream(path+"/"+file_name+".asd");
			byte[] content_asd = arq2.readAllBytes();
			arq2.close();

			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(user_Kpub);
			sig.update(conteudo);
			boolean result = sig.verify(content_asd);
			System.out.println("Protected file " + file_name +" validation result : " + result + "\n");
			String sconteudo = "";
			sconteudo = new String(conteudo, StandardCharsets.UTF_8);
			if(result) {
				System.out.println(sconteudo); 
				sconteudo = sconteudo.replaceAll("\n"," ");
				textoSeparado = sconteudo.split(" ");
				//for(int i = 0; i < textoSeparado.length; i++){
				//	System.out.println(textoSeparado[i]);
				//}
			}
			return textoSeparado;
		}catch(FileNotFoundException E1){
			System.out.println("\nARQUIVO NAO ENCONTRADO\n");
		}
		catch(IOException E2){}
		catch(NoSuchAlgorithmException E3){System.out.println("\nALGORITMO NAO ENCONTRADO\n");}
		catch(InvalidKeyException E4){System.out.println( "\nINVALID KEY\n" );}
		catch(IllegalBlockSizeException E5){System.out.println( "\nILEGGAL BLOCK SIZE\n" );}
		catch(NoSuchPaddingException E6){System.out.println( "\nNO SUCH PADDING\n" );}
		catch(BadPaddingException E7){System.out.println( "\nBAD PADDING\n" );}
		catch(SignatureException E8){System.out.println( "\nSIGNATURE FAIL\n" );}
		return null;
	}

	// recebe o nome do usuário dono do envelope digital, a chave privada que decifrará tal envelope, a chave pública que irá validar a assinatura digital e printa na tela o conteúdo do arquivo protegido
	public static void protectedFileValidation(DigitalVaultDB db, int user_id, String path, String file_name, PrivateKey user_Kpriv, PublicKey user_Kpub) {
		try{
			FileInputStream arq = new FileInputStream(path+"/"+file_name+".env");
			byte[] content_env = arq.readAllBytes();
			arq.close();

			Cipher decrypt_env = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			System.out.println( "\nStart digital envelope decryption" );
			decrypt_env.init(Cipher.DECRYPT_MODE, user_Kpriv);
			byte[] seed = decrypt_env.doFinal(content_env);

			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			sr.setSeed(seed); // Define seed a partir da decriptação do envelope
			KeyGenerator kgen = KeyGenerator.getInstance("DES");
			kgen.init(56, sr);
			SecretKey KDES = kgen.generateKey(); // recupera chave simetrica
			
			System.out.println( "\nStart cryptogram decryption" );
			byte[] conteudo = decryptCryptogram(db, user_id, path+"/", file_name, KDES);

			FileInputStream arq2 = new FileInputStream(path+"/"+file_name+".asd");
			byte[] content_asd = arq2.readAllBytes();
			arq2.close();

			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(user_Kpub);
			sig.update(conteudo);
			boolean result = sig.verify(content_asd);
			System.out.println("Protected file " + file_name +" validation result : " + result + "\n");
			String sconteudo = "";
			if(result){
				if(file_name.equals("index")) {
					long now = System.currentTimeMillis();
					Timestamp data = new Timestamp(now);
					db.insertRegisterInDB(data, 8006, db.getUserEmail(user_id), "");
					sconteudo = new String(conteudo, StandardCharsets.UTF_8);
					System.out.println(sconteudo);
					now = System.currentTimeMillis();
					data = new Timestamp(now);
					db.insertRegisterInDB(data, 8009, db.getUserEmail(user_id), "");
				}
				else{
					long now = System.currentTimeMillis();
					Timestamp data = new Timestamp(now);
					db.insertRegisterInDB(data, 8014, db.getUserEmail(user_id), file_name);
					String str = Base64.getEncoder().encodeToString(conteudo);
					byte[] decode = Base64.getDecoder().decode(str);
					sconteudo = new String(decode, StandardCharsets.UTF_8);
					FileOutputStream arqNew = new FileOutputStream(path+file_name+".new");
					arqNew.write(sconteudo.getBytes());
					arqNew.close();
				}
			}
			else {
				if(file_name.equals("index")) {
					long now = System.currentTimeMillis();
					Timestamp data = new Timestamp(now);
					db.insertRegisterInDB(data, 8008, db.getUserEmail(user_id), "");
				}
				else {
					long now = System.currentTimeMillis();
					Timestamp data = new Timestamp(now);
					db.insertRegisterInDB(data, 8016, db.getUserEmail(user_id), file_name);
				}
			}

		} catch(FileNotFoundException E1){
			System.out.println("\nARQUIVO NAO ENCONTRADO\n");
			if(file_name.equals("index")) {
				long now = System.currentTimeMillis();
				Timestamp data = new Timestamp(now);
				db.insertRegisterInDB(data, 8004, db.getUserEmail(user_id), "");
			}
		}
		catch(IOException E2){}
		catch(NoSuchAlgorithmException E3){}
		catch(InvalidKeyException E4){System.out.println( "\nVOCE NAO EH DONO DO ARQUIVO\n" );}
		catch(IllegalBlockSizeException E5){System.out.println( "\nVOCE NAO EH DONO DO ARQUIVO\n" );}
		catch(NoSuchPaddingException E6){System.out.println( "\nVOCE NAO EH DONO DO ARQUIVO\n" );}
		catch(BadPaddingException E7){System.out.println( "\nVOCE NAO EH DONO DO ARQUIVO\n" );}
		catch(SignatureException E8){System.out.println( "\nVOCE NAO EH DONO DO ARQUIVO\n" );}
	}

	// registra novo usuário no BD
	public static void registerNewUser(String path_cert, String given_pass, String grupo, DigitalVaultDB db){
		numUsuarios = db.getNumUsers();
		try{
			FileInputStream fis = new FileInputStream(path_cert);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CERT = (X509Certificate)cf.generateCertificate(fis);
			X500Principal subject = CERT.getSubjectX500Principal();
			
			int i = subject.toString().indexOf('=');
			int j = subject.toString().indexOf(',');
			String email = subject.toString().substring(i+1, j);
			String encod_cert = Base64.getEncoder().encodeToString(CERT.getEncoded());
			int gid;
			if(grupo.equals("Usuario"))
				gid = 2;
			else
				gid = 1;
			numUsuarios++;
			String salt = getAlphaNumericString(10);		
			String senhaESalt = given_pass+salt;
			String HASH = PasswordAndSaltToHash(senhaESalt);
			db.insertUserInDB(numUsuarios, email, salt, HASH, encod_cert, 0, gid);
		} catch(CertificateEncodingException E1){}
		catch(FileNotFoundException E2){}
		catch(CertificateException E3){}
	}

	public static void changeCert(int user_id, String path_cert, DigitalVaultDB db){
		try{
			FileInputStream fis = new FileInputStream(path_cert);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CERT = (X509Certificate)cf.generateCertificate(fis);
			fis.close();

			String encod_cert = Base64.getEncoder().encodeToString(CERT.getEncoded());
			db.changeUserCert(user_id, encod_cert);
		} catch(CertificateEncodingException E1){}
		catch(FileNotFoundException E2){
			long now = System.currentTimeMillis();
			Timestamp data = new Timestamp(now);
			db.insertRegisterInDB(data, 7003, db.getUserEmail(user_id), "");
		}
		catch(CertificateException E3){}
		catch(IOException E4){}
	}

	// recebe um id de usuário, uma senha recebida, um BD e retorna um valor que indica se a senha recebida corresponde a do usuário
	public static boolean comparePassword(int user_id, String given_pass, DigitalVaultDB db){
		boolean q = false;
		String salt = null;
		String hash = null;

		salt = db.getUserSalt(user_id);	// salt do usuário 
		hash = db.getUserHash(user_id);	// HEX(HASH_SHA1(senha_texto_plano + SALT))

		String givenEsalt = given_pass+salt;
		String HASH_given = PasswordAndSaltToHash(givenEsalt);

		// compara o HASH da senha fornecida com o HASH da senha do usuário
		if(hash.equals(HASH_given)){
			//System.out.println("Senha fornecida eh igual a senha do usuario!");
			q = true;
		}
		//else
		//	System.out.println("Senha fornecida NAO eh igual a senha do usuario!");

		return q;
	}
	
	public static boolean compareFullPassword(int user_id, List<int[]> given_pass, DigitalVaultDB db){
		boolean correct = false;
		
		for(int i = 0; i < Math.pow(2,given_pass.size()); i++) {
			int[] bits = new int[given_pass.size()];
		    for (int j = 0; j < given_pass.size(); j++) {
		    	if ((i & (1 << j)) == 0) {
		    		bits[j] = 0;
		    	}
		    	else {
		    		bits[j] = 1;
		    	}
		    }
		    String senha = "";
		    for (int j = 0; j < given_pass.size(); j++) {
		    	senha += Integer.toString(given_pass.get(j)[bits[j]]);
		    }
		    
		    if (comparePassword(user_id, senha, db) == true) {
		    	correct = true;
		    	break;
		    }
		}
		if (correct == true) {
			return true;
		}
		return false;
	}

	// recebe uma String senha+salt e retorna um resumo de mensagem (SHA-1) em hexadecimal 
	public static String PasswordAndSaltToHash(String StringPasswordAndSalt){
		String HASH = null;
		try{
			byte [] bytesSenhaSalt = StringPasswordAndSalt.getBytes("UTF-8");
			MessageDigest mdigest = MessageDigest.getInstance("SHA-1");
			mdigest.update(bytesSenhaSalt);
			byte[] digest = mdigest.digest();
			// converte o digest para hexadecimal
			StringBuffer buf = new StringBuffer();
			for(int i = 0; i < digest.length; i++) {
				String hex = Integer.toHexString(0x0100 + (digest[i] & 0x00FF)).substring(1);
				buf.append((hex.length() < 2 ? "0" : "") + hex);
			}
			HASH = buf.toString();
			return HASH;
		}catch(UnsupportedEncodingException E1){}
		catch(NoSuchAlgorithmException E2){}

		return HASH;
	}

	// recebe o id de um usuário e um BD para pegar o certificado do usuário em questão, decodificar, pois se encontra em BASE 64, e retorna a chave pública do certificado 
	public static PublicKey get_public_DB(int user_id, DigitalVaultDB db){
		String cert = db.getCertString(user_id);
		byte[] cert_decode = Base64.getDecoder().decode(cert);
		try{
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			ByteArrayInputStream inputStream  =  new ByteArrayInputStream(cert_decode);
			X509Certificate CERT = (X509Certificate)cf.generateCertificate(inputStream);
			PublicKey Kpub = CERT.getPublicKey();
			return Kpub;
		}catch(CertificateException E1){}

		return null;
	}

	// recebe o id de um usuário que terá sua senha mudada
	public static void changePassword(int user_id, String new_pass, DigitalVaultDB db){
		String salt = db.getUserSalt(user_id);
		String senhaEsalt = new_pass+salt;

		String HASH_new_pass = PasswordAndSaltToHash(senhaEsalt);
		db.changeUserPassword(user_id, HASH_new_pass);

		String hash = null;
		hash = db.getUserHash(user_id);	// HEX(HASH_SHA1(senha_texto_plano + SALT))
		if(HASH_new_pass.equals(hash))
			System.out.println("Senha mudada com sucesso!");
		else
			System.out.println("Senha nao foi mudada com sucesso!");
	}
	
	public static List<int[]> RandomNumberButton() {
		Random gerador = new Random();
		List<Integer> num = new ArrayList<Integer>();
		for (int i = 0; i < 10; i++) {
			num.add(i);
		}
        List<int[]> senha = new ArrayList<int[]>();
        for(int i = 0; i < 5; i++) {
        	int[] button = new int[2];
        	for(int j = 0; j < 2; j++) {
	        	int n = gerador.nextInt(10);
	        	while(!num.contains(n)) {
	        		n = gerador.nextInt(10);
	        	}
	        	button[j] = n;
	        	num.remove(num.indexOf(n));
        	}
        	senha.add(button);
        }
        return senha;
	}
	
	public static void printButtons(List<int[]> buttons) {
		for(int i = 0; i < 5; i++) {
			String options = "";
			options += Integer.toString(buttons.get(i)[0]) + " ou ";
			options += Integer.toString(buttons.get(i)[1]);
			System.out.println("Botao "+Integer.toString(i+1)+" -> " + options);
		}
		System.out.println("Botao 6 -> LIMPAR");
		System.out.println("Botao 7 -> OK");
		
	}
	
	public static List<int[]> AskPassword() {
		//instância um objeto da classe Random usando o construtor básico
		List<int[]> senha = new ArrayList<int[]>();
		List<int[]> buttons = RandomNumberButton();
        
        try {
			System.out.println("\nCofre Digital - Autenticacao");
			System.out.println("Senha Pessoal: ");
			System.out.println("SELECIONE UM BOTAO");
			printButtons(buttons);
			
			String button = myObj.nextLine();  // Read user input
			int option = Integer.parseInt(button);
			while (option != 7 || senha.size() < 8 ) {
				if(option == 7) {
			    	System.out.println("SENHA PRECISA TER ENTRE 8 e 10 NUMEROS");
			    	
			    }
			    else if(option >= 1 && option <= 5) {
			    	if(senha.size() < 10) {
			    		senha.add(buttons.get(option-1));
			    		buttons = RandomNumberButton();
			        	
			    	}
			    	else {
			    		System.out.println("SENHA ALCANCOU O TAMANHO MAXIMO");
			    		
			    	}
			    }
			    else if(option == 6) {
			    	senha.clear();
			    	System.out.println("SENHA LIMPADA");
			    }
			    else {
			    	System.out.println("BOTAO INVALIDO");
			    }
				System.out.println("\nCofre Digital - Autenticacao");
			    System.out.println("Senha Pessoal: "+"*".repeat(senha.size()));
			    System.out.println("SELECIONE UM BOTAO");
			    printButtons(buttons);
				button = myObj.nextLine();
				option = Integer.parseInt(button);
			}
		} catch (NumberFormatException e) {
			e.printStackTrace();
		}
        return senha;
	}
}
