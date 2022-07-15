import java.sql.*;

public class DigitalVaultDB {
    Connection connection = null;
    public DigitalVaultDB(String nome_db){
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:"+nome_db+".db");
            System.out.println("Conexao com BD realizada !!!!\n");
            connection.createStatement().execute("PRAGMA foreign_keys = ON");
		} catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public int getNumUsers(){
        int cont = 0;
        cont = getSizeTable("USUARIOS");
        return cont;
    }
    
    public int getSizeTable(String table){
        int cont = 0;
        final String sql = "SELECT * FROM "+table+"";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            while (resultSet.next()) {
                    cont++;
            }
            return cont;
        } catch (SQLException e) {
            return cont;
        }
    }

    public void createTables(){
        try{
            Statement statement = connection.createStatement();
            statement.execute("CREATE TABLE IF NOT EXISTS GRUPOS( GID INTEGER PRIMARY KEY, Grupo VARCHAR )");
            statement.execute("CREATE TABLE IF NOT EXISTS USUARIOS( UID INTEGER PRIMARY KEY, Email VARCHAR UNIQUE, Salt VARCHAR, HASH VARCHAR, CERT VARCHAR, CT INTEGER, BLK TIMESTAMP, GID INTEGER, ACESSOS INTEGER, CONSULTAS INTEGER, FOREIGN KEY(GID) REFERENCES GRUPOS(GID) )");
            statement.execute("CREATE TABLE IF NOT EXISTS MENSAGENS( Num INTEGER PRIMARY KEY, Descricao VARCHAR )");
            statement.execute("CREATE TABLE IF NOT EXISTS REGISTROS( Data TIMESTAMP, Num_Msg INTEGER, Email VARCHAR, Arquivo VARCHAR, FOREIGN KEY(Num_Msg) REFERENCES MENSAGENS(Num), FOREIGN KEY(Email) REFERENCES USUARIOS(Email) )");

            ResultSet rs = connection.getMetaData().getTables(null, null, null, null);
            //System.out.println("Nomes das Tabelas criadas");
            while (rs.next()) {
                //System.out.println(rs.getString("TABLE_NAME"));
                sqliteTableColumns(connection, rs.getString("TABLE_NAME"));
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void sqliteTableColumns(Connection connection, String tableName) {
        String sql = "select * from " + tableName + " LIMIT 0";
        try{
            Statement statement = connection.createStatement();
            ResultSet rs = statement.executeQuery(sql);
            ResultSetMetaData mrs = rs.getMetaData();
            //for(int i = 1; i <= mrs.getColumnCount(); i++) 
                //System.out.println(mrs.getColumnLabel(i)); 
        } catch(SQLException E1){}
    }
    
    public void startGrupos() {
    	final String sql = "INSERT INTO GRUPOS(GID, Grupo) VALUES (?, ?)";
    	try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            stmt.setInt(1, 1);
            stmt.setString(2, "Administrador");
            stmt.executeUpdate();
            stmt.setInt(1, 2);
            stmt.setString(2, "Usuario");
            stmt.executeUpdate();
        } catch(SQLException e) {
            System.out.println(e.getMessage());
        }
    }
	
	public void startMensagens() {
    	final String sql = "INSERT INTO MENSAGENS(Num, Descricao) VALUES (?, ?)";
    	try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            stmt.setInt(1, 1001);
            stmt.setString(2, "Sistema iniciado.");
            stmt.executeUpdate();
            stmt.setInt(1, 1002);
            stmt.setString(2, "Sistema encerrado.");
            stmt.executeUpdate();
			stmt.setInt(1,2001);
			stmt.setString(2, "Autenticacao etapa 1 iniciada.");
            stmt.executeUpdate();
			stmt.setInt(1,2002);
			stmt.setString(2, "Autenticaaco etapa 1 encerrada.");
            stmt.executeUpdate();
			stmt.setInt(1,2003);
			stmt.setString(2, "Login name <login_name> identificado com acesso liberado.");
            stmt.executeUpdate();
			stmt.setInt(1,2004);
			stmt.setString(2, "Login name <login_name> identificado com acesso bloqueado.");
            stmt.executeUpdate();
			stmt.setInt(1,2005);
			stmt.setString(2, "Login name <login_name> nao identificado.");
            stmt.executeUpdate();
			stmt.setInt(1,3001);
			stmt.setString(2, "Autenticacao etapa 2 iniciada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,3002);
			stmt.setString(2, "Autenticacao etapa 2 encerrada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,3003);
			stmt.setString(2, "Senha pessoal verificada positivamente para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,3004);
			stmt.setString(2, "Primeiro erro da senha pessoal contabilizado para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,3005);
			stmt.setString(2, "Segundo erro da senha pessoal contabilizado para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,3006);
			stmt.setString(2, "Terceiro erro da senha pessoal contabilizado para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,3007);
			stmt.setString(2, "Acesso do usuario <login_name> bloqueado pela autenticacao etapa 2.");
            stmt.executeUpdate();
			stmt.setInt(1,4001);
			stmt.setString(2, "Autenticacao etapa 3 iniciada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,4002);
			stmt.setString(2, "Autenticacao etapa 3 encerrada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,4003);
			stmt.setString(2, "Chave privada verificada positivamente para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,4004);
			stmt.setString(2, "Chave privada verificada negativamente para <login_name> (caminho invalido).");
            stmt.executeUpdate();
			stmt.setInt(1,4005);
			stmt.setString(2, "Chave privada verificada negativamente para <login_name> (frase secreta invalida).");
            stmt.executeUpdate();
			stmt.setInt(1,4006);
			stmt.setString(2, "Chave privada verificada negativamente para <login_name> (assinatura digital invalida).");
            stmt.executeUpdate();
			stmt.setInt(1,4007);
			stmt.setString(2, "Acesso do usuario <login_name> bloqueado pela autenticacao etapa 3.");
            stmt.executeUpdate();
			stmt.setInt(1,5001);
			stmt.setString(2, "Tela principal apresentada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,5002);
			stmt.setString(2, "Opcao 1 do menu principal selecionada por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,5003);
			stmt.setString(2, "Opcao 2 do menu principal selecionada por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,5004);
			stmt.setString(2, "Opcao 3 do menu principal selecionada por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,5005);
			stmt.setString(2, "Opcao 4 do menu principal selecionada por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,6001);
			stmt.setString(2, "Tela de cadastro apresentada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,6002);
			stmt.setString(2, "Botao cadastrar pressionado por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,6003);
			stmt.setString(2, "Senha pessoal invalida fornecida por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,6004);
			stmt.setString(2, "Caminho do certificado digital invalido fornecido por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,6005);
			stmt.setString(2, "Confirmacao de dados aceita por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,6006);
			stmt.setString(2, "Confirmacao de dados rejeitada por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,6007);
			stmt.setString(2, "Botao voltar de cadastro para o menu principal pressionado por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,7001);
			stmt.setString(2, "Tela de alteracao da senha pessoal e certificado apresentada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,7002);
			stmt.setString(2, "Senha pessoal invalida fornecida por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,7003);
			stmt.setString(2, "Caminho do certificado digital invalido fornecido por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,7004);
			stmt.setString(2, "Confirmacao de dados aceita por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,7005);
			stmt.setString(2, "Confirmacao de dados rejeitada por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,7006);
			stmt.setString(2, "Botao voltar de carregamento para o menu principal pressionado por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8001);
			stmt.setString(2, "Tela de consulta de arquivos secretos apresentada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8002);
			stmt.setString(2, "Botao voltar de consulta para o menu principal pressionado por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8003);
			stmt.setString(2, "Botao Listar de consulta pressionado por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8004);
			stmt.setString(2, "Caminho de pasta invalido fornecido por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8005);
			stmt.setString(2, "Arquivo de indice decriptado com sucesso para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8006);
			stmt.setString(2, "Arquivo de indice verificado (integridade e autenticidade) com sucesso para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8007);
			stmt.setString(2, "Falha na decriptacao do arquivo de indice para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8008);
			stmt.setString(2, "Falha na verificacao (integridade e autenticidade) do arquivo de indice para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8009);
			stmt.setString(2, "Lista de arquivos presentes no indice apresentada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8010);
			stmt.setString(2, "Arquivo <arq_name> selecionado por <login_name> para decriptacao.");
            stmt.executeUpdate();
			stmt.setInt(1,8011);
			stmt.setString(2, "Acesso permitido ao arquivo <arq_name> para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8012);
			stmt.setString(2, "Acesso negado ao arquivo <arq_name> para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8013);
			stmt.setString(2, "Arquivo <arq_name> decriptado com sucesso para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8014);
			stmt.setString(2, "Arquivo <arq_name> verificado (integridade e autenticidade) com sucesso para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8015);
			stmt.setString(2, "Falha na decriptacao do arquivo <arq_name> para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,8016);
			stmt.setString(2, "Falha na verificacao (integridade e autenticidade) do arquivo <arq_name> para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,9001);
			stmt.setString(2, "Tela de saida apresentada para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,9002);
			stmt.setString(2, "Saida nao liberada por falta de one-time password para <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,9003);
			stmt.setString(2, "Botao sair pressionado por <login_name>.");
            stmt.executeUpdate();
			stmt.setInt(1,9004);
			stmt.setString(2, "Botao voltar de sair para o menu principal pressionado por <login_name>.");
            stmt.executeUpdate();
			
        } catch(SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void insertUserInDB(int UID, String Email, String Salt, String HASH, String CERT, int CT, int GID){
        final String sql = "INSERT INTO USUARIOS(UID, Email, Salt, HASH, CERT, CT, BLK, GID, ACESSOS, CONSULTAS) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            long t = 0;
            Timestamp blk = new Timestamp(t);
            stmt.setInt(1, UID);
            stmt.setString(2, Email);
            stmt.setString(3, Salt);
            stmt.setString(4, HASH);
            stmt.setString(5, CERT);
            stmt.setInt(6, CT);
            stmt.setTimestamp(7, blk);  
            stmt.setInt(8, GID);
            stmt.setInt(9, 0);
            stmt.setInt(10, 0);
            stmt.executeUpdate();
        } catch(SQLException e) {
            System.out.println(e.getMessage());
        }
    }
	
	public void insertRegisterInDB(Timestamp data, int Num_Msg,String email, String Arquivo){
        final String sql = "INSERT INTO REGISTROS(Data, Num_Msg, Email, Arquivo) VALUES (?, ?, ?, ?)";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            stmt.setTimestamp(1, data);
            stmt.setInt(2, Num_Msg);
			if (email.equals(null) || email.length() == 0){
				stmt.setNull(3, Types.NULL);
			}
			else {
				stmt.setString(3, email);
			}
			if (Arquivo.length() == 0) {
				stmt.setNull(4, Types.NULL);
			}
			else {
				stmt.setString(4, Arquivo);
			}
            stmt.executeUpdate();
        } catch(SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    //recebe uma string que denota um usua¡rio e retorna true, caso o email desse usua¡rio se encontra no BD, e false, caso contra¡rio 
    public int searchEmail(String email){
        int q = 0;
        final String sql = "SELECT Email FROM USUARIOS";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            while (resultSet.next()) {
                String aux = resultSet.getString("Email");
                if(aux.equals(email)){
                    q = getUserUID(email);
                    return q;
                }
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        return q;
    }
    
    public int getUserUID(String email){
        int uid = -1;
        final String sql = "SELECT * FROM USUARIOS";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            while (resultSet.next()) {
                String aux = resultSet.getString("Email");
                if(aux.equals(email)){
                    uid = resultSet.getInt("UID");
                    return uid;
                }
            }
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return uid;
    }
    
    public String getUserEmail(int user_id){
    	String email = null;
        final String sql = "SELECT Email FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            email = resultSet.getString("Email");
            return email;
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return email;
    }

     // recebe um int que denota o ID do usua¡rio no BD e retorna o Salt
    public String getUserSalt(int user_id){
        String salt = null;
        final String sql = "SELECT Salt FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            salt = resultSet.getString("Salt");
            return salt;
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return salt;
    }

     // recebe um int que denota o ID do usua¡rio no BD e retorna o Digest (HEX(HASH(Salt + senha pessoal))
    public String getUserHash(int user_id){
        String hash = null;
        final String sql = "SELECT HASH FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            hash = resultSet.getString("HASH");
            return hash;
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return hash;
    }

    // recebe um int que denota o ID de um usua¡rio no BD e retorna o certificado desse usua¡rio em BASE64
    public String getCertString(int user_id){
        String cert = null;
        final String sql = "SELECT CERT FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            cert = resultSet.getString("CERT");
            return cert;
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        return cert;
    }
    
    public Timestamp getBLKTimestamp(int user_id){
        Timestamp blk = null;
        final String sql = "SELECT BLK FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            blk = resultSet.getTimestamp("BLK");
            return blk;
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        return blk;
    }
    
    public String getUserGrupo(int user_id){
        String grupo = null;
        final String sql = "SELECT Grupo FROM USUARIOS, GRUPOS WHERE UID = "+Integer.toString(user_id)+" AND USUARIOS.GID = GRUPOS.GID";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            grupo = resultSet.getString("Grupo");
            return grupo;
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        return grupo;
    }
    
    public int getUserAcessos(int user_id){
        int acessos = 0;
        final String sql = "SELECT ACESSOS FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            acessos = resultSet.getInt("ACESSOS");
            return acessos;
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        return acessos;
    }

    public void incUserConsultas(int user_id){
        final String sql_get = "SELECT CONSULTAS FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        int cons = 0;
        try{
            
            PreparedStatement stmt = connection.prepareStatement(sql_get);
            ResultSet resultSet = stmt.executeQuery();
            cons = resultSet.getInt("CONSULTAS");
            cons++;
            
            final String sql = "UPDATE USUARIOS SET CONSULTAS = ? WHERE UID = ?";
            PreparedStatement stmt2 = connection.prepareStatement(sql);
            stmt2.setString(1, Integer.toString(cons));
            stmt2.setString(2, Integer.toString(user_id));
            stmt2.executeUpdate();
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
    
    public int getUserConsultas(int user_id){
        int consultas = 0;
        final String sql = "SELECT CONSULTAS FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            consultas = resultSet.getInt("CONSULTAS");
            return consultas;
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        return consultas;
    }

    // recebe um int que denota um usua¡rio do BD e "bloqueia" tal usua¡rio
    public void setBlockUser(int user_id){
        final String sql = "UPDATE USUARIOS SET BLK = ? WHERE UID = ?";
        try{
        	long t = System.currentTimeMillis();
            Timestamp blk = new Timestamp(t);
            PreparedStatement stmt = connection.prepareStatement(sql);
            stmt.setTimestamp(1, blk);
            stmt.setString(2, Integer.toString(user_id));
            stmt.executeUpdate();
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // recebe um int que denota um usua¡rio do BD e "desbloqueia" tal usua¡rio
    public void unblockUser(int user_id){
        final String sql = "UPDATE USUARIOS SET BLK = 0 WHERE UID = ?";
        final String sql2 = "UPDATE USUARIOS SET CT = 0 WHERE UID = ?";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            stmt.setString(1, Integer.toString(user_id));
            stmt.executeUpdate();

            PreparedStatement stmt2 = connection.prepareStatement(sql2);
            stmt2.setString(1, Integer.toString(user_id));
            stmt2.executeUpdate();
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // recebe o id do usua¡rio que tera¡ sua senha mudada
    public void changeUserPassword(int user_id, String newPass){
        final String sql = "UPDATE USUARIOS SET HASH = ? WHERE UID = ?";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            stmt.setString(1, newPass);
            stmt.setString(2, Integer.toString(user_id));
            stmt.executeUpdate();
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
    
    public void deleteRow(int user_id) {
    	final String sql = "DELETE FROM USUARIOS WHERE UID = ?";
    	try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            stmt.setString(1, Integer.toString(user_id));
            stmt.executeUpdate();
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
    
    public void deleteTable(String table) {
    	final String sql = "DROP TABLE "+table+"";
    	try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            stmt.setString(1, table);
            stmt.executeUpdate();
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
    
    public void view(String table){
    	final String sql = "SELECT * FROM "+table+"";
    	try{
	    	PreparedStatement stmt = connection.prepareStatement(sql);
	        ResultSet resultSet = stmt.executeQuery();
			ResultSetMetaData rsmd = resultSet.getMetaData();
			
			int columnsNumber = rsmd.getColumnCount();                     
	
			// Iterate through the data in the result set and display it. 
	
			while (resultSet.next()) {
				//Print one row          
				for(int i = 1 ; i <= columnsNumber; i++){
	
					  System.out.print(resultSet.getString(i) + " "); //Print one element of a row
	
				}
	
				System.out.println();//Move to the next line to print the next row.           
	
			}
    	} catch (SQLException e) {
            System.out.println(e.getMessage());
        }
	}
    
    public boolean verifyBlocked(int user_id) {
        final String sql_get_CT = "SELECT CT FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        int CT = 0;
		long now = System.currentTimeMillis();
		Timestamp agora = new Timestamp(now-120000); // Tempo agora - 2 min
		Timestamp blk = getBLKTimestamp(user_id); // Tempo  bloqueio
		//System.out.println(agora.toString());
		//System.out.println(blk.toString());
		int dt = agora.compareTo(blk);
		if (dt >= 0) { // ja se passou 2 min desde o bloqueio
			return false; // nao esta bloqueado
		}
		else{
			return true; // esta bloqueado
		}
    }

    public int incUserCounter(int user_id){
        final String sql_get_CT = "SELECT CT FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        int CT = 0;
        try{
            if(verifyBlocked(user_id)){
            }
            else{
                PreparedStatement stmt = connection.prepareStatement(sql_get_CT);
                ResultSet resultSet = stmt.executeQuery();
                CT = resultSet.getInt("CT");
                CT++;
                if(CT == 3){
                    setBlockUser(user_id);
                    zeroUserCounter(user_id);
                    return 0;
                }
                final String sql = "UPDATE USUARIOS SET CT = ? WHERE UID = ?";
                PreparedStatement stmt2 = connection.prepareStatement(sql);
                stmt2.setString(1, Integer.toString(CT));
                stmt2.setString(2, Integer.toString(user_id));
                stmt2.executeUpdate();
            }
            return CT;
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return CT;
    }
    
    public void zeroUserCounter(int user_id){
        try{
	        final String sql = "UPDATE USUARIOS SET CT = 0 WHERE UID = ?";
	        PreparedStatement stmt2 = connection.prepareStatement(sql);
	        stmt2.setString(1, Integer.toString(user_id));
	        stmt2.executeUpdate();
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
    
    public void incUserAcess(int user_id){
        final String sql_get_CT = "SELECT ACESSOS FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        int CT = 0;
        try{
            PreparedStatement stmt = connection.prepareStatement(sql_get_CT);
            ResultSet resultSet = stmt.executeQuery();
            CT = resultSet.getInt("ACESSOS");
            CT++;
            final String sql = "UPDATE USUARIOS SET ACESSOS = ? WHERE UID = ?";
            PreparedStatement stmt2 = connection.prepareStatement(sql);
            stmt2.setString(1, Integer.toString(CT));
            stmt2.setString(2, Integer.toString(user_id));
            stmt2.executeUpdate();
        }catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public String getUserName(int user_id){
        String name = "";
        final String sql = "SELECT Email FROM USUARIOS WHERE UID = "+Integer.toString(user_id)+"";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            ResultSet resultSet = stmt.executeQuery();
            String aux = resultSet.getString("Email");
            int iend = aux.indexOf("@"); //this finds the first occurrence of "." 
            name = aux.substring(0 , iend); //this will give abc
            return name;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return name;
    }

    public void changeUserCert(int user_id, String cert_string){
        final String sql = "UPDATE USUARIOS SET CERT = ? WHERE UID = ?";
        try{
            PreparedStatement stmt = connection.prepareStatement(sql);
            stmt.setString(1, cert_string);
            stmt.setString(2, Integer.toString(user_id));
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
}
