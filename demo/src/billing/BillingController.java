// Demo fixture: deliberately vulnerable. Never compiled or run.
package ru.ctf.billing;

import java.io.File;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BillingController {

    private final Connection connection;

    public BillingController(Connection connection) {
        this.connection = connection;
    }

    @GetMapping("/invoice")
    public ResultSet invoice(@RequestParam String id) throws Exception {
        Statement statement = connection.createStatement();
        return statement.executeQuery("SELECT id, amount FROM invoices WHERE id = " + id);
    }

    @GetMapping("/file")
    public String file(@RequestParam String name) throws Exception {
        File target = new File(request.getParameter("name"));
        return new String(java.nio.file.Files.readAllBytes(target.toPath()));
    }

    @GetMapping("/ping")
    public void ping(@RequestParam String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
