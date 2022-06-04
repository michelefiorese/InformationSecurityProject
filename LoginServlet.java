import jakarta.servlet.http.HttpServlet;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.Date;
import java.util.Properties;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Servlet implementation class HelloWorldServlet
 */
@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private static final String USER = "postgres";
	private static final String PWD = "password";
	private static final String DRIVER_CLASS = "org.postgresql.Driver";
	private static final String DB_URL = "jdbc:postgresql://localhost:5433/InfoSecDB";

	private static Connection conn;
	
	/**
     * @see HttpServlet#HttpServlet()
     */
    public LoginServlet() {
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

	//pw
	 static String generateStorngPasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		int iterations = 1000;
		char[] chars = password.toCharArray();
		byte[] salt = getSalt();

		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 128);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

		byte[] hash = skf.generateSecret(spec).getEncoded();
		return iterations + ":" + toHex(salt) + ":" + toHex(hash);
	}

	 static byte[] getSalt() throws NoSuchAlgorithmException
	{
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[8];
		sr.nextBytes(salt);
		return salt;
	}

	 public static String toHex(byte[] array) throws NoSuchAlgorithmException
	{
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);

		int paddingLength = (array.length * 2) - hex.length();
		if(paddingLength > 0)
		{
			return String.format("%0"  +paddingLength + "d", 0) + hex;
		}else{
			return hex;
		}
	}

	 static boolean validatePassword(String originalPassword, String storedPassword)
			throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		String[] parts = storedPassword.split(":");
		int iterations = Integer.parseInt(parts[0]);

		byte[] salt = fromHex(parts[1]);
		byte[] hash = fromHex(parts[2]);

		PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(),
				salt, iterations, hash.length * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[] testHash = skf.generateSecret(spec).getEncoded();

		int diff = hash.length ^ testHash.length;
		for(int i = 0; i < hash.length && i < testHash.length; i++)
		{
			diff |= hash[i] ^ testHash[i];
		}
		return diff == 0;
	}
	 static byte[] fromHex(String hex) throws NoSuchAlgorithmException
	{
		byte[] bytes = new byte[hex.length() / 2];
		for(int i = 0; i < bytes.length ;i++)
		{
			bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
	}

	//pw
    
    public void init() throws ServletException {
		System.out.println("User \"" + USER + "\" connected to database.");
    	try {
			Class.forName(DRIVER_CLASS);
			
		    Properties connectionProps = new Properties();
		    connectionProps.put("user", USER);
		    connectionProps.put("password", PWD);

	        conn = DriverManager.getConnection(DB_URL, connectionProps);
    	} catch (ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}
    }

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		
		String email = request.getParameter("email");
		String pwd = request.getParameter("password");

		String query= "SELECT * FROM users WHERE users.email = ? ";
		try (Statement st = conn.createStatement()) {
			PreparedStatement pstmt = conn.prepareStatement( query );
			pstmt.setString( 1, email);
			ResultSet sqlRes = pstmt.executeQuery();



			if (sqlRes.next()) {
				if(isBad(email,pwd,"","")){
					request.getRequestDispatcher("login.html").forward(request, response);
				}else if(validatePassword(pwd, sqlRes.getString(4))){
						String time = new Date(System.currentTimeMillis()).toInstant().toString(); // get new login time
						// insert new login time
						st.execute(
								"UPDATE users SET lastlogin = '" + time + "' WHERE email= '" + email + "'"
						);
						request.setAttribute("email", sqlRes.getString(3));
						request.setAttribute("password", sqlRes.getString(4));
						System.out.println("Login succeeded!");
						request.setAttribute("content", "");
						request.getRequestDispatcher("home.jsp").forward(request, response);

				}else{
					request.getRequestDispatcher("login.html").forward(request, response);
				}
			} else {
				System.out.println("Login failed!");

				request.getRequestDispatcher("login.html").forward(request, response);
			}
			
		} catch (SQLException e) {
			e.printStackTrace();
			request.getRequestDispatcher("login.html").forward(request, response);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
}
