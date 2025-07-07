function togglePassword() {
    const input = document.getElementById("passwordField");
    const icon = document.getElementById("eyeBtn");
    if (input.type === "password") {
        input.type = "text";
        icon.textContent = "🙈";
    } else {
        input.type = "password";
        icon.textContent = "👁️";
    }
}

async function triggerLoginOTP() {
    const email = document.getElementById("emailField").value;
    const password = document.getElementById("passwordField").value;
    const sendBtn = document.getElementById("sendOtpBtn");
    const sendText = document.getElementById("sendOtpText");
    const spinner = document.getElementById("sendSpinner");
    const purposeField = document.getElementById("purposeField"); // 👈 reference hidden input

    if (!email || !password) return alert("Please enter both email and password.");

    sendText.textContent = "Validating...";
    spinner.classList.remove("hidden");
    sendBtn.disabled = true;

    try {
        // Step 1: Check credentials
        const validateRes = await fetch("/validate_credentials", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ email, password })
        });

        const data = await validateRes.json();

        if (data.status === "not_found") {
            alert("⚠️ No account found with this email. Redirecting to Register...");
            window.location.href = "/register";
            return;
        } else if (data.status === "error") {
            alert(data.message || "Invalid credentials.");
            return;
        }

        // ✅ Set purpose based on role
        const dynamicPurpose = data.role === "admin" ? "admin_login" : "login";
        purposeField.value = dynamicPurpose;

        // Step 2: Credentials valid, now send OTP
        sendText.textContent = "Sending OTP...";
        const otpRes = await fetch("/send_otp", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ email, password, purpose: dynamicPurpose })
        });

        if (otpRes.ok) {
            document.getElementById("otpModal").classList.remove("hidden");
            startCountdown();
        } else {
            alert("OTP sending failed. Please try again.");
        }

    } catch (err) {
        console.error("OTP Flow Error:", err);
        alert("Something went wrong.");
    } finally {
        sendText.textContent = "Send OTP";
        spinner.classList.add("hidden");
        sendBtn.disabled = false;
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

function submitLoginOTP() {
    const otp = document.getElementById("otpField").value;
    if (!otp.match(/^[A-Za-z0-9]{6}$/)) {
        alert("Enter a valid 6-character alphanumeric OTP.");
        return;
    }
    document.getElementById("otpInput").value = otp;
    document.getElementById("loginForm").submit();
}


document.addEventListener("DOMContentLoaded", function () {
    const now = new Date();

    // Format local time as 12-hour, DD/MM/YYYY
    const formattedTime = now.toLocaleString("en-GB", {
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
    });

    // Get user's time zone name
    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

    // Set the values to hidden fields
    document.getElementById("local_login_time").value = formattedTime;
    document.getElementById("time_zone").value = timeZone;
});