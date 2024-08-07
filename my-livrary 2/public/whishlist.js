document.addEventListener('DOMContentLoaded', function() {
    // Handle registration form submission
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent form submission

            // Get form values
            const fullname = document.getElementById('fullname').value;
            const email = document.getElementById('email').value;
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            // Create user object
            const user = { fullname, email, username, password };

            // Save user data to local storage
            localStorage.setItem('user', JSON.stringify(user));

            alert('Registration successful! Redirecting to login page.');

            // Redirect to login page
            window.location.href = 'login.html';
        });
    }

    // Handle login form submission
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent form submission

            // Get form values
            const username = document.getElementById('login_username').value;
            const password = document.getElementById('login_password').value;

            // Retrieve user data from local storage
            const storedUser = localStorage.getItem('user');
            if (storedUser) {
                const user = JSON.parse(storedUser);

                // Check if username and password match
                if (username === user.username && password === user.password) {
                    alert('Login successful! Redirecting to dashboard...');
                    // Redirect to dashboard page
                    window.location.href = 'dashboard.html';
                } else {
                    alert('Incorrect username or password. Please try again.');
                }
            } else {
                alert('No user registered. Please register first.');
            }
        });
    }

    // Handle wishlist button
    const wishlistButton = document.querySelector('.wishlist-btn');
    if (wishlistButton) {
        const wishlistIcon = wishlistButton.querySelector('.wishlist-icon');

        wishlistButton.addEventListener('click', () => {
            if (wishlistButton.classList.toggle('clicked')) {
                wishlistIcon.src = 'remove.png';
            } else {
                wishlistIcon.src = 'add.png';
            }
        });
    }

    // Function to simulate redirecting to a payment page
    function redirectToPaymentPage(button) {
        console.log('Redirecting to payment page for book:', button.closest('.book-item').dataset.bookTitle);
        // Add actual redirection logic here
    }

    // Load books when the page loads
    function loadBooks() {
        // Example: Load books logic here
        console.log('Loading books...');
    }
    loadBooks();

    // Handle search bar
    const searchBtn = document.getElementById('search-btn');
    if (searchBtn) {
        searchBtn.addEventListener('click', function () {
            const query = document.getElementById('search-bar').value.toLowerCase();
            const books = document.querySelectorAll('.book-item');
            
            books.forEach(book => {
                const title = book.querySelector('.book-info h3').textContent.toLowerCase();
                const author = book.querySelector('.book-info p').textContent.toLowerCase();
                if (title.includes(query) || author.includes(query)) {
                    book.style.display = 'block';
                } else {
                    book.style.display = 'none';
                }
            });
        });
    }
});
