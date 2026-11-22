
// ==================================
// SMARTBANK - JAVASCRIPT
// ==================================

// Registration Password Validation

document.addEventListener("DOMContentLoaded", function () {

    const registerForm = document.querySelector(
        'form[action*="register"]'
    );

    if (registerForm) {
        registerForm.addEventListener("submit", function (event) {

            const password = registerForm.querySelector(
                '[name="password"]'
            ).value;

            const confirmPassword = registerForm.querySelector(
                '[name="confirm_password"]'
            ).value;

            if (password !== confirmPassword) {
                event.preventDefault();
                alert("Passwords do not match!");
            }

            if (password.length < 8) {
                event.preventDefault();
                alert("Password must contain at least 8 characters!");
            }
        });
    }

    // Amount Validation

    const amountInputs = document.querySelectorAll(
        'input[name="amount"]'
    );

    amountInputs.forEach(function (input) {

        input.addEventListener("input", function () {

            if (Number(input.value) <= 0) {
                input.setCustomValidity(
                    "Please enter an amount greater than zero."
                );
            } else {
                input.setCustomValidity("");
            }

        });

    });

    // Form Submission Protection

    const forms = document.querySelectorAll("form");

    forms.forEach(function (form) {

        form.addEventListener("submit", function () {

            const button = form.querySelector(
                'button[type="submit"]'
            );

            if (button && form.checkValidity()) {
                button.textContent = "Processing...";
                button.disabled = true;
            }

        });

    });

});
