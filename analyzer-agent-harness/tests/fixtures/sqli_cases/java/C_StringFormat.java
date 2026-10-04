import java.sql.*;
class C_StringFormat {
    ResultSet c(Connection conn, String id) throws Exception {
        String sql = String.format("SELECT * FROM orders WHERE id = %s", id);
        return conn.createStatement().executeQuery(sql);
    }
}
