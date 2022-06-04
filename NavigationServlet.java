

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
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

/**
 * Servlet implementation class NavigationServlet
 */
@WebServlet("/NavigationServlet")
public class NavigationServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private static final String USER = "postgres";
	private static final String PWD = "password";
	private static final String DRIVER_CLASS = "org.postgresql.Driver";
	private static final String DB_URL = "jdbc:postgresql://localhost:5433/InfoSecDB";

	private static Connection conn;
    /**
     * @see HttpServlet#HttpServlet()
     */
    public NavigationServlet() {
        super();
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

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		
		String email = request.getParameter("email").replace("'","''");;
		String pwd = request.getParameter("password").replace("'","''");;
		String search = request.getParameter("search");



		if (request.getParameter("newMail") != null)
			request.setAttribute("content", getHtmlForNewMail(email, pwd));
		else if (request.getParameter("inbox") != null)
			request.setAttribute("content", getHtmlForInbox(email, pwd, search));
		else if (request.getParameter("sent") != null)
			request.setAttribute("content", getHtmlForSent(email));
		else if (request.getParameter("search") != null)
			request.setAttribute("content", getHtmlForInbox(email, pwd, search));
		
		request.setAttribute("email", email);
		request.setAttribute("password", pwd);
		request.getRequestDispatcher("home.jsp").forward(request, response);
	}

	private String getHtmlForInbox(String email, String pwd, String search) {
		StringBuilder output = new StringBuilder();
		try (Statement st = conn.createStatement()) {
			ResultSet sqlRes = null;

			if (isBad(search, "", "", "")) {
				search = null; // if the input contains not accepted characters set it to null
			}

			if(search==null) {
				sqlRes = st.executeQuery(
						"SELECT * FROM mail "
								+ "WHERE mail.receiver='" + email + "'"
								+ "ORDER BY mail.time DESC"
				);
			}
			else {
				sqlRes = st.executeQuery(
						"SELECT * FROM mail "
								+ "WHERE mail.receiver='" + email + "' AND mail.subject LIKE '%" + search +"%'"
								+ "ORDER BY mail.time DESC"
				);
			}
			

			output.append("<div>\r\n Searching for: " + search);

			output.append("<form action=\"NavigationServlet\" method=\"POST\">" +
					"<input type=\"text\" placeholder=\"search\" name=\"search\"/>" +
					"<input type=\"hidden\" name=\"email\" value=\"" + email + "\"/>" +
					"<input type=\"hidden\" name=\"password\" value=\"" + pwd + "\"/>" +
					"</form>");
			// get private key
			File privateKeyFile = new File("/Users/miche/Desktop/PrivateKeys/"+email+".key");

			byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			Key privateKey = keyFactory.generatePrivate(privateKeySpec);

			while (sqlRes.next()) {
				// DECRYPT BODY
				// decrypt aes key
				byte[] encryptedAESKey = Base64.getDecoder().decode(sqlRes.getString(5));

				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.PRIVATE_KEY, privateKey);
				byte[] decryptedAESKey = cipher.doFinal(encryptedAESKey);
				SecretKey aesKey = new SecretKeySpec(decryptedAESKey , 0, decryptedAESKey.length, "AES");

				// decrypt email body
				Cipher aesCipher = Cipher.getInstance("AES");
				aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

				byte[] byteCipherText = Base64.getDecoder().decode(sqlRes.getString(4));
				byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
				String decryptedMessage = new String(bytePlainText);

				// VERIFY DIGITAL SIGNATURE
				String signature = sqlRes.getString(8);

				// append this string to the html if the signature is verified
				String signatureStr = "";

				// verify signature if the email has one
				if (!signature.equals("null")) {
					// get senders public key
					File publicKeyFile = new File("publicKeys/" + sqlRes.getString(1) +".key");

					byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
					KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");

					EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
					Key publicKey = keyFactory2.generatePublic(publicKeySpec);

					// use key to decrypt signature and obtain signature hash
					byte[] encryptedHash = Base64.getDecoder().decode(signature.getBytes());
					Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher2.init(Cipher.DECRYPT_MODE, publicKey);
					byte[] signatureHash = cipher2.doFinal(encryptedHash);

					// hash the decrypted body of the email
					MessageDigest digest = MessageDigest.getInstance("SHA-256");
					byte[] hashedBody = digest.digest(decryptedMessage.getBytes(StandardCharsets.UTF_8));

					// check if the two hashes match. if yes, signature is verified
					if(Arrays.equals(signatureHash, hashedBody)) {
						signatureStr = "&emsp;&emsp;SIGNATURE:&emsp;valid";
					}
				}

				output.append("<div style=\"white-space: pre-wrap;\"><span style=\"color:grey;\">");
				output.append("FROM:&emsp;" + sqlRes.getString(1) + "&emsp;&emsp;AT:&emsp;" + sqlRes.getString(7) + signatureStr);
				output.append("</span>");
				output.append("<br><b>" + sqlRes.getString(3) + "</b>\r\n");
				output.append("<br>" + decryptedMessage);
				output.append("</div>\r\n");
				
				output.append("<hr style=\"border-top: 2px solid black;\">\r\n");
			}
			
			output.append("</div>");
			

		} catch (SQLException | IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
			return "ERROR IN FETCHING INBOX MAILS!";
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}

		return output.toString();
	}
	
	private String getHtmlForNewMail(String email, String pwd) {
		// generate token for validation and insert it in the form
		String token = "";
		try (Statement st = conn.createStatement()) {
			ResultSet res = st.executeQuery(
					"SELECT lastlogin FROM users WHERE email ='" + email + "'"
			);
			res.next();
			String time = res.getString(1);
			String originalString = email + pwd + time;

			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] encodedhash = digest.digest(originalString.getBytes(StandardCharsets.UTF_8));
			token = LoginServlet.toHex(encodedhash);
		} catch (SQLException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}


		return 
			"<form id=\"submitForm\" class=\"form-resize\" action=\"SendMailServlet\" method=\"post\">\r\n"
			+ "		<input type=\"hidden\" name=\"email\" value=\""+email+"\">\r\n"
			+ "		<input type=\"hidden\" name=\"password\" value=\""+pwd+"\">\r\n"
			+ "		<input type=\"hidden\" name=\"validationtoken\" value=\"" + token +"\">\r\n"
			+ "		<input class=\"single-row-input\" type=\"email\" name=\"receiver\" placeholder=\"Receiver\" required>\r\n"
			+ "		<input class=\"single-row-input\" type=\"text\"  name=\"subject\" placeholder=\"Subject\" required>\r\n"
			+ "		<textarea class=\"textarea-input\" name=\"body\" placeholder=\"Body\" wrap=\"hard\" required></textarea>\r\n"
			+ "		<input type=\"submit\" name=\"sent\" value=\"Send\">\r\n"
			+ "		<br>"
			+ "		<br>"
			+ "		<input type=\"checkbox\" name=\"sentSigned\" value=\"SendSigned\">\r\n"
			+ "		<label for=\"signature\"> Send signed email </label>\r\n"
			+ "	</form>";
	}
	
	private String getHtmlForSent(String email) {
		String query = "SELECT * FROM mail WHERE mail.sender= ? ORDER BY mail.time DESC";
		StringBuilder output = new StringBuilder();
		try (Statement st = conn.createStatement()) {
			PreparedStatement pstmt = conn.prepareStatement( query );
			pstmt.setString(1, email);
			ResultSet sqlRes = pstmt.executeQuery();
			output.append("<div>\r\n");

			// get private key
			File privateKeyFile = new File("/Users/miche/Desktop/PrivateKeys/"+email+".key");

			byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			Key privateKey = keyFactory.generatePrivate(privateKeySpec);
			
			while (sqlRes.next()) {
				// decrypt aes key
				byte[] encryptedAESKey = Base64.getDecoder().decode(sqlRes.getString(6));

				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.PRIVATE_KEY, privateKey);
				byte[] decryptedAESKey = cipher.doFinal(encryptedAESKey);
				SecretKey aesKey = new SecretKeySpec(decryptedAESKey , 0, decryptedAESKey.length, "AES");

				// decrypt email body
				Cipher aesCipher = Cipher.getInstance("AES");
				aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

				byte[] byteCipherText = Base64.getDecoder().decode(sqlRes.getString(4));
				byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
				String decryptedMessage = new String(bytePlainText);

				output.append("<div style=\"white-space: pre-wrap;\"><span style=\"color:grey;\">");
				output.append("TO:&emsp;" + sqlRes.getString(2) + "&emsp;&emsp;AT:&emsp;" + sqlRes.getString(7));
				output.append("</span>");
				output.append("<br><b>" + sqlRes.getString(3) + "</b>\r\n");
				output.append("<br>" + decryptedMessage);
				output.append("</div>\r\n");
				
				output.append("<hr style=\"border-top: 2px solid black;\">\r\n");
			}
			
			output.append("</div>");
			

		} catch (SQLException | IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException e) {
			e.printStackTrace();
			return "ERROR IN FETCHING INBOX MAILS!";
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		return output.toString();
	}
}
