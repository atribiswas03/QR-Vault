async function populateCountryDropdown() {
    const select = document.getElementById('country_code');
    const res = await fetch("/static/data/country-codes.json");
    const countries = await res.json();
    countries.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.dial_code;
        opt.textContent = `${c.name} (${c.dial_code})`;
        if (c.dial_code === "+91") opt.selected = true;
        select.appendChild(opt);
    });
}
function togglePassword() {
    const input = document.getElementById("passwordField");
    const icon = document.getElementById("eyeBtn");
    if (input.type === "password") {
        input.type = "text";
        icon.textContent = "🙈"; // Show crossed-eye
    } else {
        input.type = "password";
        icon.textContent = "👁️"; // Show eye
    }
}


function validatePasswordStrength(password) {
    const strength = document.getElementById("strength");
    const strong = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (strong.test(password)) {
        strength.textContent = "✅ Strong password";
        strength.classList.remove("text-yellow-400");
        strength.classList.add("text-green-400");
    } else {
        strength.textContent = "❌ Weak password: use 8+ chars, uppercase, lowercase & number.";
        strength.classList.remove("text-green-400");
        strength.classList.add("text-yellow-400");
    }
}

async function triggerOTP() {
    const email = document.getElementById("emailField").value;
    const btn = document.getElementById("otpButton");
    const text = document.getElementById("otpButtonText");
    const spinner = document.getElementById("otpSpinner");

    if (!email) return alert("Enter a valid email first!");

    btn.disabled = true;
    text.textContent = "Checking...";
    spinner.classList.remove("hidden");

    try {
        // Step 1: Check if email is already registered
        const checkRes = await fetch("/check_email", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ email })
        });

        const checkData = await checkRes.json();

        if (checkData.status === "exists") {
            alert("⚠️ This email is already registered. Please log in.");
            window.location.href = "/login";
            return;
        }

        // Step 2: Send OTP
        text.textContent = "Sending...";
        const otpRes = await fetch("/send_otp", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ email, purpose: 'register' })
        });

        if (otpRes.ok) {
            document.getElementById('otpModal').classList.remove("hidden");
            startCountdown();
        } else {
            alert("OTP sending failed. Try again.");
        }

    } catch (err) {
        console.error("OTP Send Error:", err);
        alert("Something went wrong. Try again.");
    } finally {
        text.textContent = "Send OTP";
        spinner.classList.add("hidden");
        btn.disabled = false;
    }
}



function startCountdown() {
    let seconds = 60;
    const countdown = document.getElementById("countdown");
    const expiredText = document.getElementById("otpExpired");
    const verifyBtn = document.getElementById("verifyBtn");

    const timer = setInterval(() => {
        seconds--;
        countdown.textContent = seconds;
        if (seconds <= 0) {
            clearInterval(timer);
            verifyBtn.disabled = true;
            expiredText.classList.remove("hidden");
            setTimeout(() => window.location.href = "/", 3000);
        }
    }, 1000);
}

function submitOTP() {
    const otp = document.getElementById("otpField").value;

    // Accept exactly 6 characters (letters or digits)
    if (!otp.match(/^[A-Za-z0-9]{6}$/)) {
        return alert("Enter a valid 6-character alphanumeric OTP!");
    }

    document.getElementById("otpInput").value = otp;
    document.getElementById("registerForm").submit();
}

document.addEventListener("DOMContentLoaded", () => {
    populateCountryDropdown();
    document.getElementById("passwordField").addEventListener("input", e => validatePasswordStrength(e.target.value));
});