function toggleVisibility(fieldId, btn) {
    const field = document.getElementById(fieldId);
    if (field.type === "password") {
        field.type = "text";
        btn.textContent = "🙈";
    } else {
        field.type = "password";
        btn.textContent = "👁️";
    }
}

function validateStrength() {
    const input = document.getElementById("newPass").value;
    const strengthText = document.getElementById("strengthText");
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

    if (regex.test(input)) {
        strengthText.textContent = "✅ Strong password";
        strengthText.classList.remove("text-yellow-400");
        strengthText.classList.add("text-green-400");
    } else {
        strengthText.textContent = "❌ Weak: use 8+ chars, upper, lower & number.";
        strengthText.classList.remove("text-green-400");
        strengthText.classList.add("text-yellow-400");
    }
}

// On form submit validate both
document.getElementById("resetForm")?.addEventListener("submit", function (e) {
    const pass = document.getElementById("newPass").value;
    const confirm = document.getElementById("confirmPass").value;
    const error = document.getElementById("passError");
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

    if (pass !== confirm || !regex.test(pass)) {
        e.preventDefault();
        error.classList.remove("hidden");
    }
});

function sendOtp() {
    const email = document.getElementById("emailInput").value;
    const btn = document.getElementById("sendBtn");
    const text = document.getElementById("sendText");
    const spinner = document.getElementById("spinner");

    if (!email) return alert("Please enter your registered email.");
    btn.disabled = true;
    text.textContent = "Sending...";
    spinner.classList.remove("hidden");

    fetch("/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ email, purpose: "reset" })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === "not_found") {
                alert("Email not registered! Redirecting...");
                window.location.href = "/register";
            } else if (data.status === "otp_sent") {
                document.getElementById("otpModal").classList.remove("hidden");
                startCountdown();
            } else {
                alert("Error: " + data.message);
            }
        })
        .catch(() => alert("Something went wrong."))
        .finally(() => {
            text.textContent = "Send OTP";
            spinner.classList.add("hidden");
            btn.disabled = false;
        });
}

function startCountdown() {
    let seconds = 60;
    const countdown = document.getElementById("countdown");
    const expired = document.getElementById("otpExpiredText");
    const verifyBtn = document.getElementById("verifyOtpBtn");

    const timer = setInterval(() => {
        seconds--;
        countdown.textContent = seconds;
        if (seconds <= 0) {
            clearInterval(timer);
            verifyBtn.disabled = true;
            expired.classList.remove("hidden");
            setTimeout(() => window.location.href = "/forgot-password", 3000);
        }
    }, 1000);
}

function verifyOtp() {
    const otp = document.getElementById("otpField").value;
    const email = document.getElementById("emailInput").value;

    // ✅ Allow alphanumeric 6-character OTPs
    if (!otp.match(/^[A-Za-z0-9]{6}$/)) {
        return alert("Enter a valid 6-character alphanumeric OTP!");
    }

    fetch("/verify-forgot-otp", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ otp, email })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                document.getElementById("otpModal").classList.add("hidden");
                document.getElementById("resetEmail").value = email;
                document.getElementById("resetModal").classList.remove("hidden");
            } else {
                alert("Incorrect OTP!");
            }
        })
        .catch(() => alert("Verification failed."));
}


document.getElementById("resetForm")?.addEventListener("submit", function (e) {
    const pass = document.getElementById("newPass").value;
    const confirm = document.getElementById("confirmPass").value;
    const error = document.getElementById("passError");
    const valid = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

    if (pass !== confirm || !valid.test(pass)) {
        e.preventDefault();
        error.classList.remove("hidden");
    }
});