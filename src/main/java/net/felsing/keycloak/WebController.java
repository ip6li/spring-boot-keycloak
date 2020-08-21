package net.felsing.keycloak;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;


@Controller
public class WebController {
    private static final Logger logger = LoggerFactory.getLogger(WebController.class);
    private final CustomerDAO customerDAO;
    private final Map<String, String> attributes = new HashMap<>();
    public WebController(CustomerDAO customerDAO) {
        this.customerDAO = customerDAO;
    }

    @GetMapping(path = "/")
    public String index() {
        logger.info("/ called");
        return "external";
    }

    @GetMapping(path = "/customers")
    public String customers(Principal principal, Model model) {
        addCustomers();
        Iterable<Customer> customers = customerDAO.findAll();
        model.addAttribute("customers", customers);
        model.addAttribute("username", principal.getName());
        model.addAttribute("attributes", attributes);
        dumpUser();

        return "customers";
    }

    @GetMapping(path = "/error")
    public String throwError() {
        logger.info("/error called");
        return "error";
    }

    // add customers for demonstration
    public void addCustomers() {

        Customer customer1 = new Customer();
        customer1.setAddress("1111 foo blvd");
        customer1.setName("Foo Industries");
        customer1.setServiceRendered("Important services");
        customerDAO.save(customer1);

        Customer customer2 = new Customer();
        customer2.setAddress("2222 bar street");
        customer2.setName("Bar LLP");
        customer2.setServiceRendered("Important services");
        customerDAO.save(customer2);

        Customer customer3 = new Customer();
        customer3.setAddress("33 main street");
        customer3.setName("Big LLC");
        customer3.setServiceRendered("Important services");
        customerDAO.save(customer3);
    }

    private void dumpUser() {
        try {
            KeycloakSecurityContext keycloakPrincipal = getKeycloakPrincipal();
            assert keycloakPrincipal!=null;
            Map<String, Object> otherClaims = keycloakPrincipal.getIdToken().getOtherClaims();
            otherClaims.forEach((k, v) -> {
                logger.info(k + ": " + v);
                attributes.put(k,(String) v);
            });
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }

    private KeycloakSecurityContext getKeycloakPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof KeycloakPrincipal) {
                return ((KeycloakPrincipal<KeycloakSecurityContext>) principal).getKeycloakSecurityContext();
            }
        }
        return null;
    }

}
