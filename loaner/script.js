const modal = document.getElementById("addEntryModal");
const btn = document.getElementById("addEntryBtn");
const span = document.getElementsByClassName("close-button")[0];
const form = document.getElementById("addEntryForm");
const tableBody = document.querySelector("#loanTable tbody");
const modalTitle = document.getElementById("modalTitle"); 
const entryIdInput = document.getElementById("entryId");

// Load existing data from local storage (if any)
let entries = loadEntries();
displayEntries();

// Open the modal (Add new)
btn.onclick = function() {
    modalTitle.textContent = "Add New Entry"; // Set title for adding
    form.reset();
    entryIdInput.value = ""; // Clear hidden input field
    modal.style.display = "block";
}

// Close the modal
span.onclick = function() {
    modal.style.display = "none";
}

// Close modal when clicking outside of it
window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }
}

// Handle form submission (both adding and editing)
form.onsubmit = function(event) {
    event.preventDefault();

    const entryId = entryIdInput.value; // Get entry ID if editing

    const updatedEntry = {
        person: document.getElementById("personName").value,
        book: document.getElementById("bookTitle").value,
        amount: parseFloat(document.getElementById("amount").value),
        direction: document.querySelector('input[name="direction"]:checked').value
    };

    if (entryId) {
        // Update existing entry
        const index = entries.findIndex(entry => entry.id === entryId);
        if (index !== -1) {
            entries[index] = { ...entries[index], ...updatedEntry };
        }
    } else {
        // Add new entry
        updatedEntry.id = Date.now().toString(); // Simple unique ID
        entries.push(updatedEntry);
    }

    saveEntries(entries);
    displayEntries();
    form.reset();
    modal.style.display = "none";
}

// Function to display entries in the table
function displayEntries() {
    tableBody.innerHTML = '';

    entries.forEach(entry => {
        const row = tableBody.insertRow();
        const personCell = row.insertCell();
        const bookCell = row.insertCell();
        const amountCell = row.insertCell();
        const statusCell = row.insertCell();
        const actionsCell = row.insertCell();

        personCell.textContent = entry.person;
        bookCell.textContent = entry.book;

        amountCell.textContent =  "$" + entry.amount.toFixed(2);
        amountCell.classList.add(entry.direction === "lentToMe" ? "green" : "red");

        statusCell.textContent = "Pending"; // You can add more status logic

        // Edit Button
        const editButton = document.createElement('button');
        editButton.textContent = 'Edit';
        editButton.addEventListener('click', () => {
            editEntry(entry);
        });
        actionsCell.appendChild(editButton);

        // Delete Button
        const deleteButton = document.createElement('button');
        deleteButton.textContent = 'Delete';
        deleteButton.addEventListener('click', () => {
            deleteEntry(entry.id); 
        });
        actionsCell.appendChild(deleteButton);
    });
}

// Function to edit an entry
function editEntry(entry) {
    modalTitle.textContent = "Edit Entry"; // Change modal title
    document.getElementById("personName").value = entry.person;
    document.getElementById("bookTitle").value = entry.book;
    document.getElementById("amount").value = entry.amount;
    document.querySelector(`input[name="direction"][value="${entry.direction}"]`).checked = true;
    entryIdInput.value = entry.id; // Set the entry ID for updating
    modal.style.display = "block";
}

// Function to delete an entry
function deleteEntry(entryId) {
    if (confirm("Are you sure you want to delete this entry?")) {
        entries = entries.filter(entry => entry.id !== entryId);
        saveEntries(entries);
        displayEntries();
    }
}

// Local Storage Functions
function saveEntries(entries) {
    localStorage.setItem("loanEntries", JSON.stringify(entries));
}

function loadEntries() {
    const storedEntries = localStorage.getItem("loanEntries");
    return storedEntries ? JSON.parse(storedEntries) : [];
}
// ... (rest of your JavaScript code)

// Handle form submission (both adding and editing)
form.onsubmit = function(event) {
  event.preventDefault();

  const entryId = entryIdInput.value; 

  const updatedEntry = {
    item: document.getElementById("itemName").value, // Get item name
    person: document.getElementById("personName").value,
    amount: parseFloat(document.getElementById("amount").value),
    direction: document.querySelector('input[name="direction"]:checked').value
  };

  // ... (rest of the form submission logic - same as before)
};

// Function to display entries in the table
function displayEntries() {
  tableBody.innerHTML = '';

  entries.forEach(entry => {
    // ... (other cell creation logic)

    itemCell.textContent = entry.item; // Display item name
    personCell.textContent = entry.person; // Display person's name

    // ... (rest of the display logic - same as before)
  });
}

// ... (rest of your JavaScript code)
