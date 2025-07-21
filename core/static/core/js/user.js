document.addEventListener("DOMContentLoaded", () => {
  initTimer();
  initLogoutButton();
  initNavigation();
});

// Timer
function initTimer() {
  const time = document.getElementById("time");
  function updateTimer() {
    const now = new Date();
    time.textContent = now.toLocaleString('en-GB', { hour12: false });
  }
  updateTimer();
  setInterval(updateTimer, 1000);
}

// Logout
function initLogoutButton() {
  const logoutBtn = document.getElementById("logout");
  const logoutForm = document.getElementById("logout-form");
  if (logoutBtn && logoutForm) {
    logoutBtn.addEventListener("click", e => {
      e.preventDefault();
      if (confirm("Are you sure you want to log out?")) logoutForm.submit();
    });
  }
}

// Navigation
function initNavigation() {
  const navLinks = document.querySelectorAll(".nav-links a");
  const sections = document.querySelectorAll("main .section");

  let lastActive = localStorage.getItem("activeTab") || "home";
  switchTab(lastActive);

  navLinks.forEach(link => {
    const sectionId = link.dataset.id;
    if (!sectionId) return;
    link.addEventListener("click", e => {
      e.preventDefault();
      localStorage.setItem("activeTab", sectionId);
      switchTab(sectionId);
    });
  });

  function switchTab(sectionId) {
    navLinks.forEach(link => {
      link.classList.toggle("active", link.dataset.id === sectionId);
    });
    sections.forEach(sec => {
      sec.hidden = sec.id !== sectionId;
    });
  }
}
