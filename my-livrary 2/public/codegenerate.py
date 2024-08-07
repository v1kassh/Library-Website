import os

# Function to get or initialize the file path for saving HTML files
def get_file_path():
    folder_path = "C:/Users/asus/OneDrive/Desktop/my-library/public"
    
    # Create folder if it doesn't exist
    if not os.path.exists(folder_path):
        try:
            os.makedirs(folder_path)
        except OSError as e:
            print(f"Error creating directory {folder_path}: {e}")
            return None
    
    return folder_path

# Function to generate HTML code for a book
def generate_book_html(book_title, author_name, price, count):
    # Process inputs
    book_title_upper = book_title.upper()
    book_id = ''.join(e for e in book_title if e.isalnum()).lower()
    author_name_upper = author_name.upper()

    # HTML template
    html_template = f"""
    <!-- {count}. {book_title_upper}-->
    <div class="book-item" 
    data-book-id="{book_id}" 
    data-book-title="{book_title_upper}" 
    data-book-author="{author_name_upper}" 
    data-book-cover="coverpage/{book_id}.jpg" 
    data-book-price="{price}"
    data-book-pdf="PDF/{book_id}.pdf">
        <div class="book-cover">
            <img src="coverpage/{book_id}.jpg" alt="{book_title_upper}">
        </div>
        <div class="book-details">
            <div class="book-info">
                <h3>{book_title_upper}</h3>
                <p>{author_name_upper}</p>
            </div>
            <div class="book-buttons">
                <a href="PDF/{book_id}.pdf" class="btn read-btn" target="_blank">Read</a>
                <button class="btn buy-btn" onclick="redirectToPaymentPage(this)">Buy - ${price}</button>
            <button class="wishlist-btn" aria-label="Add to Wishlist">
                <i class="fa fa-heart"></i>
            </button>
            </div>
        </div>
    </div>
    """
    return html_template

# Function to check for duplicate books in the existing HTML file
def is_duplicate_book(file_path, book_title, author_name):
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            content = file.read()
            book_title_upper = book_title.upper()
            author_name_upper = author_name.upper()
            if book_title_upper in content and author_name_upper in content:
                return True
    return False

# Function to handle main program logic
def main():
    # Get file path for saving HTML files (set to your specified folder path)
    folder_path = get_file_path()
    
    if folder_path is None:
        print("Unable to get folder path. Exiting program.")
        return
    
    # Define the path for the combined HTML file
    combined_file_path = os.path.join(folder_path, "pythoncoded.html")
    
    # Ask user from where to start counting
    try:
        start_count = int(input("Enter the starting number for counting books: "))
    except ValueError:
        print("Invalid input. Please enter an integer.")
        return

    current_count = start_count
    
    # Loop to add books to the combined HTML file
    while True:
        # User input for book details
        book_title = input("Enter the title of the book: ")
        author_name = input("Enter the author of the book: ")
        price = input("Enter the price of the book: ")
        
        # Check for duplicate book
        if is_duplicate_book(combined_file_path, book_title, author_name):
            print(f"The book '{book_title}' by '{author_name}' already exists in the file.")
            cont = input("Do you want to forcefully add this book? (yes/no): ").strip().lower()
            if cont != 'yes':
                continue
        
        # Generate HTML code for the book
        html_code = generate_book_html(book_title, author_name, price, current_count)
        
        # Append the HTML code of the current book to the combined HTML file
        with open(combined_file_path, "a") as combined_file:
            combined_file.write(html_code)
            combined_file.write("\n\n")  # Add some space between books
        
        print(f"HTML code for '{book_title}' has been added to {combined_file_path}")
        
        # Increment the count
        current_count += 1
        
        # Ask user if they want to add another book
        cont = input("Do you want to add another book? (yes/no): ").strip().lower()
        if cont != 'yes':
            break
    
    print(f"All HTML codes have been saved to {combined_file_path}")

if __name__ == "__main__":
    main()
