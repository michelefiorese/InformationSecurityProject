import jakarta.servlet.http.HttpServlet;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.util.Base64;
import java.util.Date;
import java.util.Properties;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.crypto.*;


/**
 * Servlet implementation class SendMailServlet
 */
@WebServlet("/SendMailServlet")
public class SendMailServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private static final String USER = "postgres";
	private static final String PWD = "password";
	private static final String DRIVER_CLASS = "org.postgresql.Driver";
	private static final String DB_URL = "jdbc:postgresql://localhost:5433/InfoSecDB";

	private static Connection conn;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public SendMailServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	public boolean isBad(String s1, String s2, String s3, String s4){
		String str="";
		str=str+s1;
		str=str+s2;
		str=str+s3;
		str=str+s4;
		char[] ch = new char[str.length()];
		for(int i=0;i<str.length();i++)
			ch[i]=str.charAt(i);
		for(int i=0;i<str.length();i++){
			if(str.charAt(i)=='<' || str.charAt(i)=='>' || str.charAt(i)=='\'')
				return true;
		}
		return false;
	}



    public void init() throws ServletException {
    	try {
			Class.forName(DRIVER_CLASS);
			
		    Properties connectionProps = new Properties();
		    connectionProps.put("user", USER);
		    connectionProps.put("password", PWD);
	
	        conn = DriverManager.getConnection(DB_URL, connectionProps);
		    
		    //System.out.println("User \"" + USER + "\" connected to database.");
    	
    	} catch (ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}
    }

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		
		String sender = request.getParameter("email").replace("'", "''");;
		String pwd = request.getParameter("password").replace("'", "''");;
		String receiver = request.getParameter("receiver").replace("'", "''");;
		String subject = request.getParameter("subject").replace("'", "''");;
		String body = request.getParameter("body").replace("'", "''");;
		String requestToken = request.getParameter("validationtoken");
		String signed = request.getParameter("sentSigned");
		String timestamp = new Date(System.currentTimeMillis()).toInstant().toString();

		// Construct validation token
		String validationToken = "";
		try (Statement st = conn.createStatement()) {
			ResultSet res = st.executeQuery(
					"SELECT lastlogin FROM users WHERE email ='" + sender + "'"
			);
			res.next();
			String time = res.getString(1);
			String originalString = sender + pwd + time;

			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] encodedhash = digest.digest(originalString.getBytes(StandardCharsets.UTF_8));
			validationToken = LoginServlet.toHex(encodedhash);
		} catch (SQLException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// VALIDATE TOKEN
		if (requestToken.equals(validationToken)) {
			System.out.println("Tokens are equal");

			// check if mail has to be signed, sign if needed
			String signature = "null";
			if (signed != null) {
				try {
					// hash body plaintext
					MessageDigest digest = MessageDigest.getInstance("SHA-256");
					byte[] encodedHash = digest.digest(body.getBytes(StandardCharsets.UTF_8));

					// retrieve senders private key
					File privateKeyFile = new File("/Users/miche/Desktop/PrivateKeys/" + sender + ".key");

					byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");


					EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
					Key privateKey = keyFactory.generatePrivate(privateKeySpec);

					// encrypt hashed body with key
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.ENCRYPT_MODE, privateKey);
					byte[] encryptedHash = cipher.doFinal(encodedHash);

					// set signature to encrypted hash
					signature = Base64.getEncoder().encodeToString(encryptedHash);

				} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
					e.printStackTrace();
				}
			}

			try (Statement st = conn.createStatement()) {
				// retrieve receivers public key
				File publicKeyFileR = new File("publicKeys/" + receiver +".key");

				byte[] publicKeyBytesR = Files.readAllBytes(publicKeyFileR.toPath());
				KeyFactory keyFactoryR = KeyFactory.getInstance("RSA");

				EncodedKeySpec publicKeySpecR = new X509EncodedKeySpec(publicKeyBytesR);
				Key publicKeyR = keyFactoryR.generatePublic(publicKeySpecR);

				// retrieve senders public key
				File publicKeyFileS = new File("publicKeys/" + sender +".key");

				byte[] publicKeyBytesS = Files.readAllBytes(publicKeyFileS.toPath());
				KeyFactory keyFactoryS = KeyFactory.getInstance("RSA");

				EncodedKeySpec publicKeySpecS = new X509EncodedKeySpec(publicKeyBytesS);
				Key publicKeyS = keyFactoryS.generatePublic(publicKeySpecS);

				// generate AES key
				KeyGenerator generator = KeyGenerator.getInstance("AES");
				generator.init(128); // AES size in number of bits
				SecretKey aesKey = generator.generateKey();

				// encrypt body with aes
				Cipher aesCipher = Cipher.getInstance("AES");
				aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
				byte[] newBodyBytes = aesCipher.doFinal(body.getBytes());


				// encrypt AES-key with public RSA keys
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.PUBLIC_KEY, publicKeyR);
				byte[] encryptedKeyBytesR = cipher.doFinal(aesKey.getEncoded());

				cipher.init(Cipher.PUBLIC_KEY, publicKeyS);
				byte[] encryptedKeyBytesS = cipher.doFinal(aesKey.getEncoded());

				// convert bytes
				String newBody = Base64.getEncoder().encodeToString(newBodyBytes);
				String encryptedKeyRec = Base64.getEncoder().encodeToString(encryptedKeyBytesR);
				String encryptedKeySen = Base64.getEncoder().encodeToString(encryptedKeyBytesS);


				if (!isBad(receiver, subject, body, "")) {
					st.execute(
							"INSERT INTO mail ( sender, receiver, subject, body, aeskeyR, aesKeyS, time, signature ) "
									+ "VALUES ( '" + sender + "', '" + receiver + "', '" + subject + "', '" + newBody + "', '"+ encryptedKeyRec + "', '" + encryptedKeySen+ "', '" + timestamp + "', '" + signature + "' )"
					);
				}

			} catch (SQLException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			}
			request.setAttribute("email", sender);
			request.getRequestDispatcher("home.jsp").forward(request, response);
		}
		else {
			System.out.println("Tokens are different. Request may be forged");
		}
	}

}
