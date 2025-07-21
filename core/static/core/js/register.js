// Form & Inputs
const form = document.querySelector(".form-container");

const firstName = document.getElementById("first-name");  // Watch spelling in HTML!
const lastName = document.getElementById("last-name");
const email = document.getElementById("email");
const phone = document.getElementById("phone");
const password = document.getElementById("password");
const confirmPassword = document.getElementById("confirm-password");

// Error Containers
const errorFirst = document.getElementById("error-first-name");
const errorLast = document.getElementById("error-last-name");
const errorEmail = document.getElementById("error-email");
const errorPhone = document.getElementById("error-phone");
const errorPass = document.getElementById("error-password");
const errorConfirm = document.getElementById("error-confirm-password");

// Validation Functions
function validateName(field, errorField, fieldName) {
    const value = field.value.trim();
    if (!value) {
        errorField.textContent = `${fieldName} should not be empty.`;
    } else {
        errorField.textContent = "";
    }
}

function validateEmail() {
    const value = email.value.trim();
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!value) {
        errorEmail.textContent = "Email is required.";
    } else if (!regex.test(value)) {
        errorEmail.textContent = "Enter a valid email address.";
    } else {
        errorEmail.textContent = "";
    }
}

function validatePhone() {
    const value = phone.value.trim();
    const regex = /^(?:\+254|0)?7\d{8}$/;
    if (!value) {
        errorPhone.textContent = "Phone is required.";
    } else if (!regex.test(value)) {
        errorPhone.textContent = "Enter a valid Kenyan phone number.";
    } else {
        errorPhone.textContent = "";
    }
}

function validatePassword() {
    const value = password.value.trim();
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    if (!value) {
        errorPass.textContent = "Password is required.";
    } else if (!regex.test(value)) {
        errorPass.textContent =
        "Must include uppercase, lowercase, digit, and special character.";
    } else {
        errorPass.textContent = "";
    }
    }

function validateConfirmPassword() {
    const passVal = password.value.trim();
    const confirmVal = confirmPassword.value.trim();

    if (!confirmVal) {
        errorConfirm.textContent = "Please confirm your password.";
    } else if (passVal !== confirmVal) {
        errorConfirm.textContent = "Passwords do not match.";
    } else {
        errorConfirm.textContent = "";
    }
}

// Real-time Listeners
firstName.addEventListener("input", () => validateName(firstName, errorFirst, "First name"));
lastName.addEventListener("input", () => validateName(lastName, errorLast, "Last name"));
email.addEventListener("input", validateEmail);
phone.addEventListener("input", validatePhone);
password.addEventListener("input", validatePassword);
confirmPassword.addEventListener("input", validateConfirmPassword);

// Show Password Toggle
const showPass = document.getElementById("show-pass");
showPass.addEventListener("change", () => {
    const type = showPass.checked ? "text" : "password";
    password.type = type;
    confirmPassword.type = type;
});

// On Form Submit
form.addEventListener("submit", (e) => {
    validateName(firstName, errorFirst, "First name");
    validateName(lastName, errorLast, "Last name");
    validateEmail();
    validatePhone();
    validatePassword();
    validateConfirmPassword();

    const hasError =
        errorFirst.textContent ||
        errorLast.textContent ||
        errorEmail.textContent ||
        errorPhone.textContent ||
        errorPass.textContent ||
        errorConfirm.textContent;

    if (hasError) {
        e.preventDefault();
    }
});
