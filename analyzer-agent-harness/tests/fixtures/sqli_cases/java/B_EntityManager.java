import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.*;
@RestController
class B_EntityManager {
    EntityManager em;
    @GetMapping("/b")
    Object b(@RequestParam String sort) {
        return em.createQuery("SELECT u FROM User u ORDER BY " + sort).getResultList();
    }
}
