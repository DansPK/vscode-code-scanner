import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController
class A_JdbcConcat {
    JdbcTemplate jdbc;
    @GetMapping("/a")
    Object a(@RequestParam String name) {
        return jdbc.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
