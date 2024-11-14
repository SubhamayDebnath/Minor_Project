
const menuBtn = document.querySelector(".menu-btn");
const header = document.getElementById("header");
menuBtn.addEventListener('click',()=>{
    menuBtn.classList.toggle("active");
    header.classList.toggle("active");
    document.querySelector("body").classList.toggle("overflow-hidden");
})

window.onscroll = function () {
  if (window.scrollY > 50) {
    header.classList.add("bg-black");
  } else {
    header.classList.remove("bg-black");
  }
};
