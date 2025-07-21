document.addEventListener("DOMContentLoaded", () => {
  const navLinks = document.querySelectorAll(".menu ul li a");
  const sections = document.querySelectorAll(".main-content .section");

  function activateTab(index) {
    navLinks.forEach(l => l.classList.remove("active"));
    sections.forEach(section => section.hidden = true);
    if (navLinks[index]) navLinks[index].classList.add("active");
    if (sections[index]) sections[index].hidden = false;
    localStorage.setItem("activeTabIndex", index);
  }
  navLinks.forEach((link, index) => {
    link.addEventListener("click", e => {
      e.preventDefault();
      activateTab(index);
    });
  });
  const savedIndex = parseInt(localStorage.getItem("activeTabIndex"), 10);
  if (!isNaN(savedIndex) && navLinks[savedIndex] && sections[savedIndex]) {
    activateTab(savedIndex);
  } else {
    activateTab(0);
  }
});
