const header = document.getElementById('header');
window.onscroll = function() {
    if (window.scrollY > 50) { 
        header.classList.add('bg-dark');
    } else {
        header.classList.remove('bg-dark');
    }
};