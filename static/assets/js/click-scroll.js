const links = document.querySelectorAll(".click-scroll");

// Menambahkan event listener pada masing-masing link
links.forEach((link) => {
  link.addEventListener("click", function (e) {
    // Menghentikan perilaku default (scrolling biasa)
    e.preventDefault();

    // Mendapatkan ID dari link yang diklik
    const targetId = this.getAttribute("href").substring(1);
    const targetElement = document.getElementById(targetId);

    // Melakukan scroll dengan halus ke elemen yang dituju
    targetElement.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  });
});

$('.click-scroll[href="/"]').click(function (e) {
  e.preventDefault(); // Mencegah halaman reload saat klik link
  $("html, body").animate(
    {
      scrollTop: 0, // Scroll ke posisi paling atas
    },
    300
  ); // Durasi animasi dalam milidetik
});
