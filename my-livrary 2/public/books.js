// Sample book data (replace with actual data or API calls)
const booksData = [
    { id: 1, title: "Book 1", author: "Author A", genre: "Fiction" },
    { id: 2, title: "Book 2", author: "Author B", genre: "Non-Fiction" },
    { id: 3, title: "Book 3", author: "Author C", genre: "Sci-Fi" },
    { id: 4, title: "Book 4", author: "Author D", genre: "Mystery" },
    // Add more books as needed
];

// Function to display books
function displayBooks(books) {
    const bookList = document.getElementById("book-list");

    // Clear existing content
    bookList.innerHTML = "";

    // Create HTML for each book and append to the list
    books.forEach(book => {
        const bookItem = document.createElement("div");
        bookItem.classList.add("book-item");
        bookItem.innerHTML = `
            <h3>${book.title}</h3>
            <p><strong>Author:</strong> ${book.author}</p>
            <p><strong>Genre:</strong> ${book.genre}</p>
        `;
        bookList.appendChild(bookItem);
    });
}

// Function to filter books by genre
function filterBooksByGenre(genre) {
    const filteredBooks = booksData.filter(book => book.genre === genre);
    displayBooks(filteredBooks);
}

// Event listener for genre filters (example)
document.addEventListener("DOMContentLoaded", () => {
    displayBooks(booksData); // Initial display of all books

    const genreFilters = document.querySelectorAll(".genre-filter");
    genreFilters.forEach(filter => {
        filter.addEventListener("click", () => {
            const genre = filter.dataset.genre;
            filterBooksByGenre(genre);
        });
    });
});
