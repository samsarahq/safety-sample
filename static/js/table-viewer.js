class TableViewer {
    constructor() {
        this.currentPage = 1;
        this.rowsPerPage = 10;
        this.totalPages = 1;
        this.currentTableData = [];
        this.sortColumn = null;
        this.sortDirection = 'asc';
        
        // Initialize when DOM is ready
        document.addEventListener('DOMContentLoaded', () => this.initialize());
    }

    initialize() {
        // Set up event listeners
        const refreshButton = document.getElementById('refreshButton');
        const prevPage = document.getElementById('prevPage');
        const nextPage = document.getElementById('nextPage');
        const rowsPerPageSelect = document.getElementById('rowsPerPage');
        const tableSelect = document.getElementById('tableSelect');
        
        if (refreshButton) {
            refreshButton.addEventListener('click', () => this.handleRefreshClick());
        }
        if (prevPage) {
            prevPage.addEventListener('click', () => this.handlePrevPage());
        }
        if (nextPage) {
            nextPage.addEventListener('click', () => this.handleNextPage());
        }
        if (rowsPerPageSelect) {
            rowsPerPageSelect.addEventListener('change', () => this.handleRowsPerPageChange());
        }
        if (tableSelect) {
            tableSelect.addEventListener('change', (e) => this.handleTableSelect(e));
        }

        // Initialize with default rows per page
        if (rowsPerPageSelect) {
            this.rowsPerPage = parseInt(rowsPerPageSelect.value) || 10;
        }
    }

    sortData(data, column, direction) {
        return [...data].sort((a, b) => {
            const aVal = a[column];
            const bVal = b[column];
            
            // Handle different data types
            if (typeof aVal === 'number' && typeof bVal === 'number') {
                return direction === 'asc' ? aVal - bVal : bVal - aVal;
            }
            
            // Handle null values
            if (aVal === null) return direction === 'asc' ? 1 : -1;
            if (bVal === null) return direction === 'asc' ? -1 : 1;
            
            // Default string comparison
            return direction === 'asc' 
                ? String(aVal).localeCompare(String(bVal))
                : String(bVal).localeCompare(String(aVal));
        });
    }

    createSortableHeaders(columns) {
        const thead = document.getElementById('dataTableHead').querySelector('tr');
        thead.innerHTML = '';
        
        columns.forEach(column => {
            const th = document.createElement('th');
            th.className = 'px-4 py-2 text-left cursor-pointer hover:bg-gray-100 border';
            
            const headerContent = document.createElement('div');
            headerContent.className = 'flex items-center gap-2';
            
            const headerText = document.createElement('span');
            headerText.textContent = column;
            headerContent.appendChild(headerText);
            
            // Add sort indicator
            const sortIndicator = document.createElement('span');
            sortIndicator.className = 'sort-indicator';
            headerContent.appendChild(sortIndicator);
            
            th.appendChild(headerContent);
            
            th.addEventListener('click', () => this.handleSort(column));
            
            thead.appendChild(th);
        });
    }

    handleSort(column) {
        // Update sort direction
        if (this.sortColumn === column) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = 'asc';
        }
        
        // Update sort indicators
        document.querySelectorAll('.sort-indicator').forEach(indicator => {
            indicator.textContent = '';
        });
        
        // Find and update the clicked column's indicator
        const headers = document.querySelectorAll('#dataTableHead th');
        headers.forEach(header => {
            if (header.textContent.includes(column)) {
                header.querySelector('.sort-indicator').textContent = 
                    this.sortDirection === 'asc' ? '↑' : '↓';
            }
        });
        
        // Sort and update display
        this.currentTableData = this.sortData(this.currentTableData, column, this.sortDirection);
        this.displayTableData({
            columns: Object.keys(this.currentTableData[0] || {}),
            rows: this.currentTableData.map(row => Object.values(row)),
            total_records: this.currentTableData.length
        });
    }

    async fetchTableData(tableName) {
        try {
            console.log(`Fetching data for table: ${tableName}, page: ${this.currentPage}`);
            const response = await fetch(`/view-table-data/${tableName}?page=${this.currentPage}&per_page=${this.rowsPerPage}`);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('Error response:', errorText);
                throw new Error(`HTTP error! status: ${response.status}, details: ${errorText}`);
            }
            
            const data = await response.json();
            console.log('Received data:', data);
            
            if (data.error) {
                throw new Error(data.error);
            }

            // Store the full data for sorting
            this.currentTableData = data.rows.map(row => {
                const obj = {};
                data.columns.forEach((col, i) => obj[col] = row[i]);
                return obj;
            });

            return data;
        } catch (error) {
            console.error('Error fetching table data:', error);
            alert('Error fetching table data: ' + error.message);
            return null;
        }
    }

    displayTableData(data) {
        const table = document.getElementById('dataTable');
        const tbody = document.getElementById('dataTableBody');
        const pagination = document.getElementById('pagination');
        const pageInfo = document.getElementById('pageInfo');

        if (!table || !tbody || !pagination || !pageInfo) {
            console.error('Required elements not found');
            return;
        }

        // Clear existing content
        tbody.innerHTML = '';

        // Create sortable headers if they don't exist
        if (!this.sortColumn) {
            this.createSortableHeaders(data.columns);
        }

        // Add rows
        data.rows.forEach(row => {
            const tr = document.createElement('tr');
            row.forEach(cell => {
                const td = document.createElement('td');
                td.textContent = cell === null ? '' : cell;
                td.className = 'border px-4 py-2';
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });

        // Update pagination
        this.totalPages = Math.ceil(data.total_records / this.rowsPerPage);
        pageInfo.textContent = `Page ${this.currentPage} of ${this.totalPages} (${data.total_records} total records)`;
        
        // Show table and pagination
        table.classList.remove('hidden');
        pagination.classList.remove('hidden');

        // Update pagination buttons
        const prevButton = document.getElementById('prevPage');
        const nextButton = document.getElementById('nextPage');
        if (prevButton) prevButton.disabled = this.currentPage <= 1;
        if (nextButton) nextButton.disabled = this.currentPage >= this.totalPages;
    }

    handleTableSelect(event) {
        if (event.target.value) {
            this.currentPage = 1;
            this.sortColumn = null;
            this.sortDirection = 'asc';
            this.handleRefreshClick();
        } else {
            const table = document.getElementById('dataTable');
            const pagination = document.getElementById('pagination');
            if (table) table.classList.add('hidden');
            if (pagination) pagination.classList.add('hidden');
        }
    }

    handleRowsPerPageChange() {
        const rowsPerPageSelect = document.getElementById('rowsPerPage');
        if (rowsPerPageSelect) {
            this.rowsPerPage = rowsPerPageSelect.value === 'all' ? 
                Number.MAX_SAFE_INTEGER : 
                parseInt(rowsPerPageSelect.value);
            this.currentPage = 1;
            this.handleRefreshClick();
        }
    }

    async handleRefreshClick() {
        const tableSelect = document.getElementById('tableSelect');
        if (!tableSelect) {
            console.error('Table select element not found');
            return;
        }

        const tableName = tableSelect.value;
        if (!tableName) {
            alert('Please select a table');
            return;
        }
        
        const data = await this.fetchTableData(tableName);
        if (data) {
            this.displayTableData(data);
        }
    }

    async handlePrevPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            const tableSelect = document.getElementById('tableSelect');
            const tableName = tableSelect.value;
            const data = await this.fetchTableData(tableName);
            if (data) {
                this.displayTableData(data);
            }
        }
    }

    async handleNextPage() {
        if (this.currentPage < this.totalPages) {
            this.currentPage++;
            const tableSelect = document.getElementById('tableSelect');
            const tableName = tableSelect.value;
            const data = await this.fetchTableData(tableName);
            if (data) {
                this.displayTableData(data);
            }
        }
    }
}

// Initialize the table viewer
const tableViewer = new TableViewer();