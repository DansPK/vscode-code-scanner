import java.sql.*;
class E_SafePrepared {
    ResultSet e(Connection conn, String name) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }
}
