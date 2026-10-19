package app;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserServlet extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String id = request.getParameter("id");
        try {
            Statement st = conn.createStatement();
            // rempart-expect: CODE-SQL-INJECTION
            ResultSet rs = st.executeQuery("SELECT * FROM users WHERE id = '" + request.getParameter("id") + "'");
            // rempart-safe: CODE-SQL-INJECTION
            PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
            ps.setString(1, id);
            ps.executeQuery();
            // rempart-expect: CODE-CMD-INJECTION
            Runtime.getRuntime().exec("nslookup " + request.getParameter("host"));
        } catch (Exception e) {
            response.sendError(500);
        }
    }
}
