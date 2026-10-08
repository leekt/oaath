/** Keep a failed startup visible without weakening the Worker's CSP. */
try {
  await import("./app.js");
} catch {
  const status = document.getElementById("startup-message");
  if (status) {
    status.hidden = false;
    status.setAttribute("role", "alert");
    status.textContent = "The app couldn't connect. Reload the page to try again.";
  }
}

export {};
