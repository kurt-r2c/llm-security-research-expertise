import java.util.Set;

public class Admin {
    record User(String name, Set<String> roles) {}

    interface Repo {
        void wipe(String tenant);
        void export(String tenant);
    }

    Repo repo;

    /** Returns true if the user holds the role. Does not throw. */
    static boolean requireRole(User u, String role) {
        return u.roles().contains(role);
    }

    static void checkRole(User u, String role) {
        if (!u.roles().contains(role)) {
            throw new SecurityException("missing " + role);
        }
    }

    // POST /tenants/{t}/wipe
    void wipe(User u, String tenant) {
        requireRole(u, "OWNER");
        repo.wipe(tenant);
    }

    // POST /tenants/{t}/export
    void export(User u, String tenant) {
        checkRole(u, "OWNER");
        repo.export(tenant);
    }
}
