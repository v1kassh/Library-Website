document.addEventListener('DOMContentLoaded', function() {
    // Handle registration form submission
    let registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent form submission

            // Get form values
            let fullname = document.getElementById('fullname').value;
            let email = document.getElementById('email').value;
            let username = document.getElementById('username').value;
            let password = document.getElementById('password').value;

            // Create user object
            let user = {
                fullname: fullname,
                email: email,
                username: username,
                password: password
            };

            // Save user data to local storage
            localStorage.setItem('user', JSON.stringify(user));

            alert('Registration successful! Redirecting to login page.');

            // Redirect to login page
            window.location.href = 'login.html';
        });
    }

    // Handle login form submission
    let loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent form submission

            // Get form values
            let username = document.getElementById('login_username').value;
            let password = document.getElementById('login_password').value;

            // Retrieve user data from local storage
            let storedUser = localStorage.getItem('user');
            if (storedUser) {
                let user = JSON.parse(storedUser);

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
    const button = document.querySelector('.wishlist-btn');
    if (button) {
        const icon = button.querySelector('.wishlist-icon');
    
        button.addEventListener('click', () => {
            if (button.classList.toggle('clicked')) {
                icon.src = 'remove.png';
            } else {
                icon.src = 'add.png';
            }
        });
    }

    // Function to simulate redirecting to a payment page
    function redirectToPaymentPage(button) {
        // Example: Redirect logic here
        console.log('Redirecting to payment page for book:', button.closest('.book-item').dataset.bookTitle);
    }

    // Load books when the page loads
    function loadBooks() {
        // Example: Load books logic here
    }
    loadBooks();

    // Handle search bar
    document.getElementById('search-btn').addEventListener('click', function () {
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
});
