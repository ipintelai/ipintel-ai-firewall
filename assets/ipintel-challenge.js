let startTS = Date.now();
let moves = 0;

document.addEventListener("mousemove", () => moves++);

const check = document.getElementById("ipintel-check");
const btn   = document.getElementById("ipintel-continue");
const err   = document.getElementById("ipintel-error");

if (check && btn) {

    check.addEventListener("change", () => {

        if (check.checked) {
            btn.classList.add("enabled");
        } else {
            btn.classList.remove("enabled");
        }
    });

    btn.addEventListener("click", async () => {

        // Block clicks if not enabled
        if (!btn.classList.contains("enabled")) return;

        // Disable visual + interaction during request
        btn.classList.remove("enabled");

        let payload = {
            start: startTS,
            click: Date.now(),
            moves: moves,
            target: IPINTEL_TARGET
        };

        const res = await fetch(IPINTEL_AJAX + "?action=ipintel_challenge_verify", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload)
        });

        const data = await res.json();

        if (!data.success) {
            err.textContent = data.data.msg;

            // Re-enable after error
            btn.classList.add("enabled");
            return;
        }

        window.location = data.data.redirect;
    });
}

