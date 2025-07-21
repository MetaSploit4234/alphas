const form = document.getElementById("login-form");
const phone = document.getElementById("phone");
const password = document.getElementById("password");

const showPass = document.getElementById("show-pass");

const errorPhone = document.getElementById("error-phone");
const errorPassword = document.getElementById("error-password");
const errorGlobal = document.getElementById("error-global");

showPass.addEventListener("change", () => {
    password.type = showPass.checked ? "text" : " password";
});

function validatePhone() {
    const value = phone.value.trim();
    const regexPhone = /^(?:\+254|0)?7\d{8}$/;

    if (!value) {
        errorPhone.innerText = "Phone should not be empty!";
    } else if (!regexPhone.test(value)) {
        errorPhone.innerText = "Enter a valid Kenyan phone number!";
    } else {
        errorPhone.innerText = "";
    }
}

function validatePassword() {
    const passValue = password.value.trim();
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    if (!passValue) {
        errorPassword.innerText = "Password should not be empty!";
    } else if (passValue.length < 8) {
        errorPassword.innerText = "Password must be at least 8 characters.";
    } else if (!passRegex.test(passValue)) {
        errorPassword.innerText =
            "Password must include uppercase, lowercase, digit, and special character.";
    } else {
        errorPassword.innerText = "";
    }
}

phone.addEventListener("input", validatePhone);
password.addEventListener("input", validatePassword);

form.addEventListener("submit", (e) => {
    validatePhone();
    validatePassword();

    const hasError =
        errorPhone.innerText !== "" || errorPassword.innerText !== "";

    if (hasError) {
        errorGlobal.innerText = "Please, fix errors!";
        e.preventDefault();

    } else {
        errorGlobal.innerText = "";
    }
});
