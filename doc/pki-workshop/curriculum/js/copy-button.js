/* Add a copy button to targeted elements */

document.addEventListener("DOMContentLoaded", () => {
  // if browser does not support navigator.clipboard...
  if (!navigator.clipboard) return;

  // Select all targets
  const targets = document.querySelectorAll("pre.command, pre.copy");

  targets.forEach((target) => {
    if (target.classList.contains("no-copy")) return;

    const code = target.querySelector("code");
    if (!code) return;  // <code> not found, don't add copy button

    const button = document.createElement("button");
    button.className = "copy-button";
    button.textContent = "Copy";
    target.prepend(button);

    // Add click functionality
    button.addEventListener("click", async () => {
      try {
        // Copy text to clipboard
        await navigator.clipboard.writeText(code.innerText);

        // Visual feedback
        const originalText = button.textContent;
        button.textContent = "Copied!";
        button.classList.add("copied");

        // Reset after 2 seconds
        setTimeout(() => {
          button.textContent = originalText;
          button.classList.remove("copied");
        }, 2000);
      } catch (err) {
        console.error("Failed to copy:", err);
        button.textContent = "Error";
      }
    });
  });
});
