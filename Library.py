import streamlit as st
import json
import os

# Ensure the library file exists and is valid
def ensure_library_file():
    if not os.path.exists("library.json"):
        with open("library.json", "w") as file:
            json.dump([], file)  # Write an empty list as the initial content

# Load & Save library data
def load_library():
    try:
        with open("library.json", "r") as file:
            content = file.read().strip()
            if not content:
                return []  # Return an empty list if the file is empty
            return json.loads(content)  # Load JSON content if not empty
    except FileNotFoundError:
        return []  # Return empty list if the file does not exist
    except json.JSONDecodeError:
        return []  # Return empty list if the file contains invalid JSON

def save_library():
    with open("library.json", "w") as file:
        json.dump(library, file, indent=4)

# Ensure the library file exists and is initialized
ensure_library_file()

# Initialize library
library = load_library()

# Header
st.markdown('<h1 style="color:blue">Prepared by Devan Das Mehrani AI Student</h1>', unsafe_allow_html=True)

# Title
st.title("Personal Library Manager")

# Sidebar menu
menu = st.sidebar.radio("Select an option", ["View Library", "Add Book", "Remove Book", "Search Book", "Save and Exit"])

# View Library
if menu == "View Library":
    st.subheader("Your Library")
    if library:
        st.table(library)
    else:
        st.write("No book in your library. Add some books!")

# Add Book
elif menu == "Add Book":
    st.subheader("Add a New Book")
    title = st.text_input("Title")
    author = st.text_input("Author")
    year = st.number_input("Year", min_value=2022, max_value=2100, step=1)
    genre = st.text_input("Genre")
    read_status = st.checkbox("Mark as Read")

    if st.button("Add Book"):
        library.append({
            "title": title,
            "author": author,
            "year": year,
            "genre": genre,
            "read_status": read_status
        })
        save_library()
        st.success("Book added successfully!")
        #st.rerun()

# Remove Book
elif menu == "Remove Book":
    st.subheader("Remove a Book")
    book_titles = [book["title"] for book in library]

    if book_titles:
        selected_book = st.selectbox("Select a book to remove", book_titles)
        if st.button("Remove Book"):
            library = [book for book in library if book["title"] != selected_book]
            save_library()
            st.success("Book removed successfully!")
            #st.rerun()
    else:
        st.warning("No book in your library. Add some books!")

# Search Book
elif menu == "Search Book":
    st.subheader("Search a Book")
    search_term = st.text_input("Enter title or author name")

    if st.button("Search"):
        results = [
            book for book in library
            if search_term.lower() in book["title"].lower() or search_term.lower() in book["author"].lower()
        ]

        if results:
            st.table(results)
        else:
            st.warning("No book found!")

# Save and Exit
elif menu == "Save and Exit":
    save_library()
    st.success("Library saved successfully!")
