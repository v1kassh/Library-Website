from pdf2image import convert_from_path
import os

# Define the directory containing PDF files
pdf_directory = r'C:\Users\asus\OneDrive\Desktop\books\PDF'

# Ensure Poppler bin directory is in PATH (if not already added)
poppler_path = r'C:\Users\asus\Downloads\Release-24.02.0-0\poppler-24.02.0\Library\bin'
os.environ['PATH'] += ';' + poppler_path

# Output directory for saving images
output_directory = r'C:\Users\asus\OneDrive\Desktop\my-livrary\public\coverpage'

# Create the output directory if it doesn't exist
os.makedirs(output_directory, exist_ok=True)

# Loop through each PDF file in the directory
for filename in os.listdir(pdf_directory):
    if filename.endswith('.pdf'):
        pdf_path = os.path.join(pdf_directory, filename)
        
        try:
            # Ask user for the page number of the cover page
            cover_page_number = input(f"Enter the page number containing the cover page for {filename}: ")
            cover_page_number = int(cover_page_number)  # Convert input to integer
            
            # Convert PDF to images (adjust parameters as needed)
            images = convert_from_path(pdf_path, first_page=cover_page_number, last_page=cover_page_number)
            
            if images:
                # Save the cover page as JPEG with custom filename
                output_filename = os.path.join(output_directory, f"{filename.replace('.pdf', '')}.jpg")
                
                # Check if the file already exists
                if os.path.exists(output_filename):
                    overwrite = input(f"The cover image {output_filename} already exists. Do you want to overwrite it? (yes/no): ")
                    if overwrite.lower() != 'yes':
                        continue  # Skip saving if user doesn't want to overwrite
                
                images[0].save(output_filename, 'JPEG')
                print(f'Cover image saved as {output_filename} successfully.')
            else:
                print(f'No images converted for {filename}.')
        
        except ValueError:
            print(f"Invalid page number entered for {filename}. Please enter a valid integer.")
        except Exception as e:
            print(f'Error converting {filename}: {str(e)}')
