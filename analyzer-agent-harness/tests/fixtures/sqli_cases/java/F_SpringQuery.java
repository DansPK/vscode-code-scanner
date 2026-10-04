import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
interface F_SpringQuery extends JpaRepository<Object, Long> {
    @Query(value = "SELECT * FROM users WHERE name = :name", nativeQuery = true)
    Object safe(@Param("name") String name);
}
