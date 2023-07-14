package cd.go.authorization.cognitomfasinglestep.cognito;

import java.util.function.Predicate;

public abstract class UserRolePredicate implements Predicate<String> {
    private final String role;

    public UserRolePredicate(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }
}
