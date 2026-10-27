import java.sql.*;
import java.util.Scanner;

public class UserAuthApp {

    private static final String URL =
            "jdbc:mysql://localhost:3306/user_auth";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD =
            "Spiderman@10";

    private static final Scanner sc = new Scanner(System.in);

    private static Connection getConnection()
            throws SQLException {
        return DriverManager.getConnection(
                URL, DB_USER, DB_PASSWORD);
    }

    private static void registerUser() {
        System.out.print("Enter username: ");
        String username = sc.nextLine().trim();

        System.out.print("Enter email: ");
        String email = sc.nextLine().trim();

        System.out.print("Enter password (minimum 8 characters): ");
        String password = sc.nextLine();

        if (username.isEmpty() || email.isEmpty()
                || password.length() < 8) {
            System.out.println("Invalid input.");
            return;
        }

        String hash = BCrypt.hashpw(
                password, BCrypt.gensalt(12));

        String sql = "INSERT INTO users "
                + "(username, email, password_hash) "
                + "VALUES (?, ?, ?)";

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setString(1, username);
            ps.setString(2, email);
            ps.setString(3, hash);
            ps.executeUpdate();

            System.out.println("Registration successful!");

        } catch (SQLIntegrityConstraintViolationException e) {
            System.out.println("Email already registered.");
        } catch (SQLException e) {
            System.out.println("Registration error: "
                    + e.getMessage());
        }
    }

    private static void loginUser() {
        System.out.print("Enter email: ");
        String email = sc.nextLine().trim();

        System.out.print("Enter password: ");
        String password = sc.nextLine();

        String sql = "SELECT password_hash FROM users "
                + "WHERE email = ?";

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setString(1, email);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next() && BCrypt.checkpw(
                        password, rs.getString("password_hash"))) {
                    System.out.println("Valid login! Welcome.");
                } else {
                    System.out.println(
                            "Invalid email or password.");
                }
            }

        } catch (SQLException e) {
            System.out.println("Login error: "
                    + e.getMessage());
        }
    }

    public static void main(String[] args) {
        while (true) {
            System.out.println("\n=== USER AUTHENTICATION ===");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");

            String choice = sc.nextLine().trim();

            switch (choice) {
                case "1":
                    registerUser();
                    break;
                case "2":
                    loginUser();
                    break;
                case "3":
                    System.out.println("Goodbye!");
                    sc.close();
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }
}
