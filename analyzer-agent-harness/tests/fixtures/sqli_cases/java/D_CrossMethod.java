import java.sql.*;
import org.springframework.web.bind.annotation.*;
@RestController
class D_CrossMethod {
    Connection conn;
    @GetMapping("/d")
    Object d(@RequestParam String name) throws Exception { return find(name); }
    private ResultSet find(String n) throws Exception {
        return conn.createStatement().executeQuery(buildQuery(n));
    }
    private String buildQuery(String n) { return "SELECT * FROM users WHERE name = '" + n + "'"; }
}
