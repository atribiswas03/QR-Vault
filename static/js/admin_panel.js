function showLogoutConfirm() {
    document.getElementById('logoutModal').classList.remove('hidden');
}

function hideLogoutConfirm() {
    document.getElementById('logoutModal').classList.add('hidden');
}

function confirmLogout() {
    window.location.href = "/logout";
}
function openEmailModal(email) {
    document.getElementById('emailTarget').value = email;
    document.getElementById('emailModal').classList.remove('hidden');
}

function closeEmailModal() {
    document.getElementById('emailModal').classList.add('hidden');
} function showManageAdminsModal() {
    document.getElementById('manageAdminsModal').classList.remove('hidden');
}

function closeManageAdminsModal() {
    document.getElementById('manageAdminsModal').classList.add('hidden');
}

function showDeleteConfirm(email) {
    document.getElementById('deleteEmailInput').value = email;
    document.getElementById('deleteConfirmModal').classList.remove('hidden');
}

function closeDeleteConfirm() {
    document.getElementById('deleteConfirmModal').classList.add('hidden');
}

function makeMotherAdmin(email) {
    document.getElementById('promoteEmailInput').value = email;
    document.getElementById('promoteForm').submit();
}



document.addEventListener("DOMContentLoaded", function () {
    const sendOtpBtn = document.getElementById("sendOtpBtn");
    const spinner = document.getElementById("sendSpinner");
    const btnText = document.getElementById("sendBtnText");
    const timerBox = document.getElementById("otp-timer");

    sendOtpBtn.addEventListener("click", async function () {
        const email = document.getElementById("email").value.trim();
        const re_email = document.getElementById("re_email").value.trim();

        // 🚫 Hide the timer before sending OTP
        timerBox.classList.add("hidden");

        if (!email || !re_email) {
            alert("⚠️ Please fill in both email fields.");
            return;
        }

        if (email !== re_email) {
            alert("⚠️ Emails do not match.");
            return;
        }

        // Show spinner
        spinner.classList.remove("hidden");
        btnText.textContent = "Sending...";

        try {
            const response = await fetch("/request-admin-otp", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ email, re_email })
            });

            const result = await response.json();

            // ✅ Start countdown only if OTP was sent successfully
            if (!result.success) {
                alert(result.message);
            } else {
                startOtpCountdown();
                btnText.textContent = "OTP Sent";
                sendOtpBtn.disabled = true;
                sendOtpBtn.classList.add("opacity-60", "cursor-not-allowed");
            }


        } catch (error) {
            console.error("Error sending OTP:", error);
            alert("❌ An error occurred while sending OTP.");
        }

        // Reset button
        spinner.classList.add("hidden");
        btnText.textContent = "Send OTP";
    });
});

let countdownInterval;
function startOtpCountdown(duration = 120) {  // 2 minutes = 120 seconds
    clearInterval(countdownInterval); // Reset any previous timer
    const countdownEl = document.getElementById('countdown');
    const timerBox = document.getElementById('otp-timer');
    let time = duration;

    timerBox.classList.remove("hidden");
    countdownEl.classList.remove("text-red-500"); // Reset color if previously expired

    countdownInterval = setInterval(() => {
        const minutes = String(Math.floor(time / 60)).padStart(2, '0');
        const seconds = String(time % 60).padStart(2, '0');
        countdownEl.textContent = `${minutes}:${seconds}`;

        if (time <= 0) {
            clearInterval(countdownInterval);
            countdownEl.textContent = "Expired";
            countdownEl.classList.add("text-red-500");
        }

        time--;
    }, 1000);
}

let otpAttemptsLeft = 2;

document.getElementById("verify-otp-form").addEventListener("submit", async function (e) {
    e.preventDefault();

    const otp = document.getElementById("otp").value.trim();
    const warningBox = document.getElementById("otp-warning");

    if (!otp) {
        warningBox.textContent = "⚠️ Please enter the OTP.";
        warningBox.classList.remove("hidden");
        return;
    }

    try {
        const res = await fetch("/verify-admin-otp", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ otp })
        });

        const result = await res.json();

        if (result.success) {
            alert("✅ Admin added successfully.");
            window.location.reload();
        } else {
            otpAttemptsLeft--;

            if (otpAttemptsLeft > 0) {
                warningBox.textContent = `❌ Incorrect OTP. You have ${otpAttemptsLeft} attempt${otpAttemptsLeft === 1 ? '' : 's'} left.`;
                warningBox.classList.remove("hidden");
            } else {
                warningBox.textContent = "❌ Too many failed attempts. Reloading...";
                setTimeout(() => {
                    closeManageAdminsModal();  // Your modal closing function
                    window.location.reload();
                }, 1500);
            }
        }
    } catch (err) {
        console.error("Error verifying OTP:", err);
        warningBox.textContent = "❌ Server error. Please try again.";
        warningBox.classList.remove("hidden");
    }
});


function confirmDelete(email) {
    document.getElementById("deleteAdminEmail").value = email;
    document.getElementById("deleteConfirmModal").classList.remove("hidden");
}

function closeDeleteModal() {
    document.getElementById("deleteConfirmModal").classList.add("hidden");
}

function confirmMakeMother(email) {
    document.getElementById("motherAdminEmail").value = email;
    document.getElementById("motherConfirmModal").classList.remove("hidden");
}

function closeMotherModal() {
    document.getElementById("motherConfirmModal").classList.add("hidden");
}

function confirmRemoveMotherAdmin(email) {
    document.getElementById("removeMotherEmail").value = email;
    document.getElementById("removeMotherAdminModal").classList.remove("hidden");
}

function closeRemoveMotherModal() {
    document.getElementById("removeMotherAdminModal").classList.add("hidden");
}