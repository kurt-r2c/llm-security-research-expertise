import java.util.Map;

public class AccountService {
    Map<Long, Account> accounts;

    record Account(long id, long ownerId) {}
    record User(long id, boolean admin) {}

    boolean canDelete(User u, Account a) {
        return u.admin() || a.ownerId() == u.id();
    }

    void assertCanDelete(User u, Account a) {
        if (!canDelete(u, a)) {
            throw new SecurityException("not allowed");
        }
    }

    // DELETE /accounts/{id}
    void deleteAccount(User u, long id) {
        Account a = accounts.get(id);
        canDelete(u, a);
        accounts.remove(id);
    }

    // POST /accounts/{id}/close
    void closeAccount(User u, long id) {
        Account a = accounts.get(id);
        assertCanDelete(u, a);
        accounts.remove(id);
    }
}
