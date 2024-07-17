document.addEventListener("DOMContentLoaded", function () {
  const textarea = document.getElementById("secret");

  textarea.addEventListener("input", function () {
    this.style.height = "auto";
    this.style.height = this.scrollHeight + "px";
  });

  textarea.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
      e.preventDefault();
    }
  });
});
