document.addEventListener('DOMContentLoaded', function() {
    const themeRadios = document.querySelectorAll('input[name="theme"]');

    // Check localStorage for saved theme
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.body.classList.add(savedTheme + '-theme');
        themeRadios.forEach(radio => {
            if (radio.value === savedTheme) {
                radio.checked = true;
            }
        });
    }

    themeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            document.body.classList.remove('light-theme', 'dark-theme');
            document.body.classList.add(this.value + '-theme');
            localStorage.setItem('theme', this.value);
        });
    });
});
