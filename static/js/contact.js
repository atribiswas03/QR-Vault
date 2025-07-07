window.addEventListener("DOMContentLoaded", () => {
    const popup = document.getElementById("feedbackPopup");
    if (popup) {
        setTimeout(() => {
            popup.classList.add("hidden");
        }, 3000);
    }
});
document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("contactForm");

    form.addEventListener("submit", function (e) {
        const timeInput = document.getElementById("local_time");
        const zoneInput = document.getElementById("time_zone");

        if (!timeInput.value || !zoneInput.value) {
            e.preventDefault(); // Stop submission
            setTimeout(() => form.submit(), 100); // Delay submit until values are set
        }
    });

    const now = new Date();
    const formattedTime = now.toLocaleString("en-GB", {
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
    });

    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

    document.getElementById("local_time").value = formattedTime;
    document.getElementById("time_zone").value = timeZone;
});
