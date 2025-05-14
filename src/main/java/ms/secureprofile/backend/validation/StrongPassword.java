package ms.secureprofile.backend.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = StrongPasswordValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface StrongPassword {
    String message() default "Password must contain at least one uppercase letter, one digit and one special character";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
