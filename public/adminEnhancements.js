/*
 * Enhancements for the admin portal.
 *
 * This script adds the ability to download the steps table as an Excel file
 * using SheetJS (xlsx). It also lays the groundwork for sorting and
 * filtering the steps table if desired in the future. The steps data is
 * loaded into the allSteps array when loadSteps() is called.
 */

// Array to store all step entries fetched from the API
let allSteps = [];

// Save a reference to the original loadSteps function (if defined) so we can
// call it later and populate allSteps. We expect the admin page to define
// loadSteps() in its inline script.
const originalLoadSteps = typeof loadSteps === 'function' ? loadSteps : null;

// Override the global loadSteps to capture data into allSteps and then call
// the original implementation to render the table.
window.loadSteps = async function() {
  try {
    const res = await fetch('/admin/steps');
    allSteps = await res.json();
    // Call the original implementation to render rows if available
    if (originalLoadSteps) {
      originalLoadSteps();
    } else {
      // Fallback: render nothing here; admin page will handle rendering
    }
  } catch (err) {
    console.error('Failed to load steps:', err);
  }
};

// Function to download the steps table as an Excel file
function downloadStepsAsExcel() {
  if (!allSteps || allSteps.length === 0) {
    alert('Det finnes ingen data å laste ned ennå.');
    return;
  }
  // Transform data into a simple array of objects for each row
  const exportData = allSteps.map(entry => ({
    Dato: entry.date,
    Ansatt: entry.employee_name,
    Lokasjon: entry.location_name,
    Skritt: entry.steps
  }));
  const workbook = XLSX.utils.book_new();
  const worksheet = XLSX.utils.json_to_sheet(exportData);
  XLSX.utils.book_append_sheet(workbook, worksheet, 'Registreringer');
  XLSX.writeFile(workbook, 'registreringer.xlsx');
}

// Attach event listeners once the DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  const downloadButton = document.getElementById('downloadXlsx');
  if (downloadButton) {
    downloadButton.addEventListener('click', downloadStepsAsExcel);
  }
});