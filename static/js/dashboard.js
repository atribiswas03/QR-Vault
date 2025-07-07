// === QR Vault JS (Cleaned & Final) ===

// ────────── GLOBAL VARIABLES ────────── //
let otpExpiryTimer = null;
let deleteId = null;
let profileSubmitting = false;

// ────────── MODAL TOGGLES ────────── //
function toggleModal() {
  document.getElementById("qrModal").classList.toggle("hidden");
}

function showLogoutConfirm() {
  const modal = document.getElementById("logoutModal");
  modal.classList.remove("hidden");
  modal.classList.add("flex");
}
function hideLogoutConfirm() {
  const modal = document.getElementById("logoutModal");
  modal.classList.remove("flex");
  modal.classList.add("hidden");
}

// ────────── QR GENERATION LOGIC ────────── //
async function handleQRSubmit(event) {
  event.preventDefault();

  const form = document.getElementById("qrForm");
  const formData = new FormData(form);

  const response = await fetch("/generate_qr", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    alert("❌ Failed to generate QR.");
    return;
  }

  const contentDisposition = response.headers.get("Content-Disposition");
  let filename = "qr_code.png";
  if (contentDisposition && contentDisposition.includes("filename=")) {
    filename = contentDisposition.split("filename=")[1].replace(/['"]/g, "").trim();
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  // ✅ Force redirect to dashboard so entries update
  setTimeout(() => {
    window.location.href = "/dashboard";
  }, 800);
}

// ────────── DELETE QR LOGIC ────────── //
function showDeleteConfirm(id) {
  deleteId = id;
  const modal = document.getElementById("deleteModal");
  modal.classList.remove("hidden");
  modal.classList.add("flex");
}
function hideDeleteConfirm() {
  deleteId = null;
  const modal = document.getElementById("deleteModal");
  modal.classList.remove("flex");
  modal.classList.add("hidden");
}

// ────────── FILE UPLOAD VALIDATION ────────── //
function handleFileUpload() {
  const file = document.getElementById("fileUpload").files[0];
  const uploadText = document.getElementById("uploadText");

  if (!file) {
    uploadText.classList.remove("bg-animate");
    uploadText.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5-5m0 0l5 5m-5-5v12" />
      </svg>
      <span>Upload File</span>`;
    return;
  }

  const maxSize = 11 * 1024 * 1024;
  if (file.size > maxSize) {
    document.getElementById("sizeWarningModal").classList.remove("hidden");
    document.getElementById("fileUpload").value = "";
    uploadText.classList.remove("bg-animate");
    uploadText.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5-5m0 0l5 5m-5-5v12" />
      </svg>
      <span>Upload File</span>`;
  } else {
    uploadText.classList.add("bg-animate");
    uploadText.innerHTML = `<span>✔ File Selected</span>`;
  }
}

// ────────── CLOSE WARNING MODAL ────────── //
function closeWarningModal() {
  document.getElementById("sizeWarningModal").classList.add("hidden");
  location.reload();
}

// ────────── CLOSE DECODED POPUP MANUALLY ────────── //
function closeDecodedPopup() {
  const popup = document.getElementById("decodedPopup");
  if (popup) popup.classList.add("hidden");
}

// ────────── VALIDATE QR FORM ────────── //
function validateQRForm() {
  const text = document.getElementById("secretText").value.trim();
  const file = document.getElementById("fileUpload").files[0];

  if (!text && !file) {
    alert("⚠️ Please enter text or upload a file.");
    return false;
  }
  return true;
}

// ────────── DELETE & COPY LISTENERS ────────── //
document.addEventListener("DOMContentLoaded", () => {
  const deleteBtn = document.getElementById("confirmDeleteBtn");
  if (deleteBtn) {
    deleteBtn.addEventListener("click", () => {
      if (!deleteId) {
        alert("⚠️ No item selected.");
        return;
      }
      fetch(`/delete_qr/${deleteId}`, { method: "DELETE" })
        .then(res => res.json())
        .then(data => {
          if (data.status === "success") location.reload();
          else alert("❌ Failed to delete the QR entry.");
        })
        .catch(() => alert("⚠️ Something went wrong. Please try again."))
        .finally(() => hideDeleteConfirm());
    });
  }

  const copyBtn = document.getElementById("copyBtn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const message = document.getElementById("decodedMessage")?.innerText;
      if (!message) return;

      navigator.clipboard.writeText(message).then(() => {
        const toast = document.getElementById("copyToast");
        if (toast) {
          toast.classList.remove("hidden");
          setTimeout(() => toast.classList.add("hidden"), 2000);
        }
      });
    });
  }

  // Decoded message auto-close
  const decodedPopup = document.getElementById("decodedPopup");
  const closeTimer = document.getElementById("closeTimer");
  if (decodedPopup && !decodedPopup.classList.contains("hidden")) {
    let countdown = 10;
    closeTimer.textContent = countdown;
    const autoClose = setInterval(() => {
      countdown--;
      closeTimer.textContent = countdown;
      if (countdown <= 0) {
        decodedPopup.classList.add("hidden");
        clearInterval(autoClose);
      }
    }, 1000);
  }
});


// ────────── SHOW PROFILE MODAL ────────── //

function openProfileModal() {
  const modal = document.getElementById("profileModal");
  if (!modal) return;

  // Fetch user profile details
  fetch('/get_profile_data')
    .then(response => response.json())
    .then(data => {
      if (data.error) {
        showCustomWarning(data.error);
        return;
      }

      // Fill in the fields
      document.getElementById('profile_name').value = data.username || '';
      document.getElementById('profile_email').value = data.email || '';
      const phone = data.phone || '';
      const code = data.country_code || '+91';

      // Separate phone from code if not stored separately
      if (phone.startsWith(code)) {
        document.getElementById('profile_country_code').value = code;
        document.getElementById('profile_phone').value = phone.substring(code.length);
      } else {
        document.getElementById('profile_country_code').value = code;
        document.getElementById('profile_phone').value = phone;
      }

      // Show the modal
      modal.classList.remove("hidden");
      modal.classList.add("flex");
    })
    .catch(err => {
      console.error("Error fetching profile:", err);
      showCustomWarning("❌ Failed to load profile. Please try again.");
    });
}

// ────────── HIDE PROFILE MODAL ────────── //
function closeProfileModal() {
  const modal = document.getElementById("profileModal");
  if (modal) {
    modal.classList.remove("flex");
    modal.classList.add("hidden");
  }
}
// ────────── LOAD COUNTRY CODES ────────── //
async function loadCountryCodes(selectedCode = "+91") {
  try {
    const response = await fetch("/static/data/country-codes.json");
    const countryCodes = await response.json();

    const select = document.getElementById("profile_country_code");
    select.innerHTML = "";
    countryCodes.forEach(({ dial_code, name }) => {
      const option = document.createElement("option");
      option.value = dial_code;
      option.textContent = `${name} (${dial_code})`;
      if (dial_code === selectedCode) option.selected = true;
      select.appendChild(option);
    });
  } catch (err) {
    console.error("Failed to load country codes:", err);
  }
}

// ────────── FETCH PROFILE DATA ────────── //
let currentPassword = ""; // Global variable for comparison

async function fetchProfileData() {
  try {
    const res = await fetch("/get_profile_data");
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    // Extract and clean phone parts
    const fullPhone = data.phone || "";
    const countryCode = data.country_code || "+91";
    const phone = fullPhone.startsWith(countryCode)
      ? fullPhone.replace(countryCode, "")
      : fullPhone;

    // Populate profile fields if elements exist
    if (document.getElementById("profile_name"))
      document.getElementById("profile_name").value = data.username || "";

    if (document.getElementById("profile_email"))
      document.getElementById("profile_email").value = data.email || "";

    if (document.getElementById("profile_phone"))
      document.getElementById("profile_phone").value = phone;

    // Save old password for validation (ensure it's provided by backend securely)
    currentPassword = data.decrypted_password || "";

    // Load country code dropdown
    await loadCountryCodes(countryCode);

  } catch (err) {
    console.error(err);
    alert("❌ Failed to load profile data.");
  }
}


fetchProfileData();

// ────────── PROFILE FORM SUBMIT ────────── //
document.getElementById("profileForm")?.addEventListener("submit", function (e) {
  e.preventDefault();
  if (profileSubmitting) return;
  profileSubmitting = true;

  const username = document.getElementById("profile_name").value.trim();
  const email = document.getElementById("profile_email").value.trim();
  const countryCode = document.getElementById("profile_country_code").value;
  const phone = document.getElementById("profile_phone").value.trim();
  const fullPhone = countryCode + phone;
  const newPassword = document.getElementById("new_password")?.value.trim();
  const otp = document.getElementById("password_otp")?.value.trim();

  if (!phone.match(/^[0-9]+$/)) {
    alert("⚠️ Phone must contain digits only.");
    profileSubmitting = false;
    return;
  }

  if (newPassword && (!otp || otp.length === 0)) {
    alert("⚠️ Please enter the OTP to update your password.");
    profileSubmitting = false;
    return;
  }

  const formData = new FormData();
  formData.append("username", username);
  formData.append("email", email);
  formData.append("phone", phone);
  formData.append("country_code", countryCode);
  formData.append("new_password", newPassword);
  formData.append("password_otp", otp);

  fetch("/update_profile", {
    method: "POST",
    body: formData,
  })
    .then(data => {
      if (data.success) {
        showSuccessPopup(); // ✅ Show success popup
      } else {
        const otpWarning = document.getElementById("otpWarning");
        if (otpWarning && data.message?.toLowerCase().includes("otp")) {
          otpWarning.textContent = data.message;
          otpWarning.classList.remove("hidden");
        } else {
          showCustomWarning(data.message || "❌ Update failed.");
        }
      }
    })

    .catch(() => showCustomWarning("❌ Server error. Try again later."))
    .finally(() => (profileSubmitting = false));
});


function togglePasswordVisibility() {
  const passwordInput = document.getElementById("new_password");
  const eyeIcon = document.getElementById("eyeIcon");

  if (passwordInput.type === "password") {
    passwordInput.type = "text";
    eyeIcon.textContent = "🙈";
  } else {
    passwordInput.type = "password";
    eyeIcon.textContent = "👁️";
  }
}

function validatePasswordStrength() {
  const password = document.getElementById("new_password").value.trim();
  const errorMsg = document.getElementById("passwordError");
  const sendBtn = document.getElementById("sendOtpBtn");

  const strongPasswordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;

  if (strongPasswordRegex.test(password)) {
    errorMsg.classList.add("hidden");
    sendBtn.disabled = false;
  } else {
    errorMsg.classList.remove("hidden");
    sendBtn.disabled = true;
  }
}


function showCustomWarning(msg) {
  const modal = document.getElementById("customWarningModal");
  const message = document.getElementById("warningMessage");
  if (modal && message) {
    message.textContent = msg;
    modal.classList.remove("hidden");
  }
}


function closeCustomWarning() {
  const modal = document.getElementById("customWarningModal");
  if (modal) modal.classList.add("hidden");
}


let otpTimerInterval = null;

function sendOTPForPassword(button) {
  const password = document.getElementById("new_password").value.trim();
  const email = document.getElementById("profile_email").value.trim();
  const otpField = document.getElementById("otpFieldContainer");
  const sendText = document.getElementById("sendOtpText");
  const loader = document.getElementById("otpLoader");

  if (!password || !email) {
    showCustomWarning("⚠️ Email or password is missing.");
    return;
  }

  if (password === currentPassword) {
    showCustomWarning("⚠️ New password cannot be same as the old password.");
    return;
  }

  button.disabled = true;
  sendText.classList.add("opacity-50");
  loader.classList.remove("hidden");

  fetch("/send_password_otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: email,
      new_password: password
    }),
  })
    .then((res) => res.json())
    .then((data) => {
      if (data.status !== "success") {
        showCustomWarning(data.message || "❌ Failed to send OTP.");
        resetOTPButton();
        otpField.classList.add("hidden");
      } else {
        otpField.classList.remove("hidden"); // ✅ Show OTP container
        const otpInput = document.getElementById("password_otp");
        if (otpInput) otpInput.classList.remove("hidden"); // ✅ Show OTP input too
        otpInput.focus(); // Optional: focus cursor on input
        startOTPTimer(button, sendText, otpField);

      }
    })
    .catch(() => {
      showCustomWarning("❌ Server error. Try again.");
      resetOTPButton();
      otpField.classList.add("hidden");
      const otpInput = document.getElementById("password_otp");
      if (otpInput) otpInput.classList.add("hidden");

    })
    .finally(() => {
      loader.classList.add("hidden");
      sendText.classList.remove("opacity-50");
    });
}




function startOTPTimer(button, sendText, otpField) {
  let secondsRemaining = 120;

  const updateBtn = document.getElementById("updateProfileBtn");
  if (updateBtn) updateBtn.disabled = true; // ✅ Disable Update button

  button.disabled = true;
  sendText.textContent = `Wait 2:00`;

  if (otpTimerInterval) clearInterval(otpTimerInterval);

  otpTimerInterval = setInterval(() => {
    secondsRemaining--;

    const minutes = Math.floor(secondsRemaining / 60);
    const seconds = secondsRemaining % 60;
    sendText.textContent = `Wait ${minutes}:${seconds.toString().padStart(2, '0')}`;

    if (secondsRemaining <= 0) {
      clearInterval(otpTimerInterval);
      sendText.textContent = "Send OTP";
      button.disabled = false;

      // ✅ Re-enable Update button
      if (updateBtn) updateBtn.disabled = false;

      // ✅ Hide OTP field after 2 min
      if (otpField) otpField.classList.add("hidden");
    }
  }, 1000);
}



function resetOTPButton() {
  const button = document.getElementById("sendOtpBtn");
  const sendText = document.getElementById("sendOtpText");
  const loader = document.getElementById("otpLoader");

  clearInterval(otpTimerInterval);
  button.disabled = false;
  sendText.textContent = "Send OTP";
  loader.classList.add("hidden");
}

function checkOtpEntered() {
  const otp = document.getElementById("password_otp")?.value.trim();
  const updateBtn = document.getElementById("updateProfileBtn");

  const otpWarning = document.getElementById("otpWarning");
  if (otpWarning) otpWarning.classList.add("hidden"); // Hide warning on input

  if (otp && otp.length === 6) {
    updateBtn.disabled = false;
  } else {
    updateBtn.disabled = true;
  }
}




function verifyPasswordOtp() {
  const email = document.getElementById("profile_email").value.trim();
  const otp = document.getElementById("password_otp").value.trim();
  const otpWarning = document.getElementById("otpWarning");
  const verifyBtn = document.getElementById("verifyOtpBtn");
  const updateBtn = document.getElementById("updateProfileBtn");

  if (!otp || otp.length !== 6) {
    otpWarning.textContent = "⚠️ Please enter a valid 6-digit OTP.";
    otpWarning.classList.remove("hidden");
    return;
  }

  verifyBtn.disabled = true;
  verifyBtn.textContent = "⏳ Verifying...";

  fetch("/verify_password_otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, otp }),
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        otpWarning.classList.add("hidden");
        updateBtn.disabled = false;

        verifyBtn.textContent = "✅ OTP Verified";
        verifyBtn.classList.remove("bg-indigo-600");
        verifyBtn.classList.add("bg-green-600");
      } else {
        otpWarning.textContent = data.message || "❌ Invalid OTP.";
        otpWarning.classList.remove("hidden");
        verifyBtn.textContent = "❌ Try Again";
      }
    })
    .catch(() => {
      otpWarning.textContent = "❌ Server error. Try again.";
      otpWarning.classList.remove("hidden");
      verifyBtn.textContent = "❌ Try Again";
    })
    .finally(() => {
      verifyBtn.disabled = false;
    });
}
