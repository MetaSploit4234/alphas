document.addEventListener("DOMContentLoaded", () => {
  const navLinks = document.querySelectorAll(".menu ul li a");
  const sections = document.querySelectorAll(".main-content .section");
  navLinks.forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      navLinks.forEach(l => l.classList.remove("active"));
      link.classList.add("active");
      const sectionId = link.textContent.trim().toLowerCase().replace(/\s+/g, "-");
      sections.forEach(sec => sec.hidden = true);
      const target = document.getElementById(sectionId);
      if (target) target.hidden = false;
    });
  });
});
