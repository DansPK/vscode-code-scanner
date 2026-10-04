import java.sql.*;
import javax.servlet.http.*;

public class UserDao {
    public ResultSet find(HttpServletRequest req, Connection conn) throws Exception {
        String name = req.getParameter("name");
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public void run(HttpServletRequest req) throws Exception {
        Runtime.getRuntime().exec("ping " + req.getParameter("host"));
    }
}
