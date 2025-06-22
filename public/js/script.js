document.addEventListener("DOMContentLoaded", () => {
  const forms = document.querySelectorAll("form");
  forms.forEach((form) => {
    form.addEventListener("submit", (e) => {
      const inputs = form.querySelectorAll("input[required], select[required]");
      let valid = true;
      inputs.forEach((input) => {
        if (!input.value.trim()) {
          valid = false;
          input.style.borderColor = "#dc3545";
        } else {
          input.style.borderColor = "#e0e0e0";
        }
      });
      if (!valid) {
        e.preventDefault();
        alert("Please fill all required fields.");
        return;
      }
      const button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      button.textContent = "Processing...";
    });
  });
});
