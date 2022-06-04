
import jakarta.servlet.http.HttpServlet;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.Date;
import java.util.Properties;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class RegisterServlet
 */
@WebServlet("/RegisterServlet")
public class RegisterServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
    
	private static final String USER = "postgres";
	private static final String PWD = "password";
	private static final String DRIVER_CLASS = "org.postgresql.Driver";
	private static final String DB_URL = "jdbc:postgresql://localhost:5433/InfoSecDB";
    
	private static Connection conn;
	
    /**
     * @see HttpServlet#HttpServlet()
     */
    public RegisterServlet() {
        super();
    }

	public KeyPair genKey() throws NoSuchAlgorithmException {
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		return keyGen.generateKeyPair();
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
		
		// The replacement escapes apostrophe special character in order to store it in SQL
		String name = request.getParameter("name").replace("'", "''");
		String surname = request.getParameter("surname").replace("'", "''");;
		String email = request.getParameter("email").replace("'", "''");;
		String badPwd = request.getParameter("password").replace("'", "''");;
		String strongPwd = "";
		String time = new Date(System.currentTimeMillis()).toInstant().toString();

		try {
			strongPwd= LoginServlet.generateStorngPasswordHash(badPwd);
			System.out.println(strongPwd);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}

		try (Statement st = conn.createStatement()) {
			if (!isBad(name, surname, email, badPwd)) {
				String query = "SELECT * FROM users WHERE users.email = ? ";
				try(Statement stReg =conn.createStatement()){
					PreparedStatement pstmt = conn.prepareStatement( query );
					pstmt.setString(1, email);
					ResultSet sqlRes = pstmt.executeQuery();
					if (sqlRes.next()) {
						System.out.println("Email already registered!");
						request.getRequestDispatcher("register.html").forward(request, response);

					} else {
						KeyPair keyPair=genKey();
						PrivateKey privateKey = keyPair.getPrivate();
						PublicKey publicKey = keyPair.getPublic();
						try (FileOutputStream fos = new FileOutputStream("/Users/miche/Desktop/PrivateKeys/"+email+".key")) {
							fos.write(privateKey.getEncoded());
						}
						try (FileOutputStream fos = new FileOutputStream(email+".key")) {
							fos.write(publicKey.getEncoded());
						}
						st.execute(
								"INSERT INTO users ( name, surname, email, password, lastlogin) "
										+ "VALUES ( '" + name + "', '" + surname + "', '" + email + "', '" + strongPwd + "' , '" + time + "')"
						);

						request.setAttribute("email", email);
						request.setAttribute("password", strongPwd);

						System.out.println("Registration succeeded!");
						request.getRequestDispatcher("home.jsp").forward(request, response);
					}

				} catch (SQLException e) {
					e.printStackTrace();
					request.getRequestDispatcher("login.html").forward(request, response);
				}
			}
			else {
				request.getRequestDispatcher("register.html").forward(request, response);
			}
		} catch (SQLException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			request.getRequestDispatcher("register.html").forward(request, response);
		}
	}
}
