/**
 * Dashboard initialization and core functionality fixes
 * Add this script at the end of your HTML just before the closing </body> tag
 */

// Make sure all charts are properly initialized
let chartInitializationComplete = false;

// Main initialization function - called after DOM is fully loaded
function initializeDashboard() {
    console.log("Starting dashboard initialization...");
    
    // Fix Select2 initialization
    if ($.fn.select2) {
        $('#org-filter').select2({
            placeholder: 'Select organizations',
            allowClear: true,
            width: '100%'
        });
    } else {
        console.error("Select2 plugin not loaded!");
    }
    
    // Initialize charts (if they exist and aren't initialized yet)
    if (!chartInitializationComplete) {
        try {
            initializeCharts();
            chartInitializationComplete = true;
            
            // Process chart data and update visualizations
            const processedChartData = processChartData(chartData);
            updateCharts(processedChartData);
            
            // Initialize ranking tables
            updateRankingTables();
            
            console.log("Charts initialized successfully");
            
            // Make sure the default view is correct
            showDefaultView();
            
            // Setup event listeners for view buttons
            setupViewButtons();
        } catch (e) {
            console.error("Error initializing charts:", e);
        }
    }
    
    // Add a slight delay before resizing to ensure everything is rendered
    setTimeout(() => {
        try {
            if (typeof resizeTrendCharts === 'function') {
                resizeTrendCharts();
            }
            console.log("Charts resized after initialization");
        } catch (e) {
            console.error("Error resizing charts:", e);
        }
    }, 500);
}

// Show the default view (charts)
function showDefaultView() {
    try {
        // Make sure charts view is visible by default
        document.getElementById('chartsView').classList.remove('hidden');
        document.getElementById('rankingView').classList.add('hidden');
        document.getElementById('predictView').classList.add('hidden');
        
        // Set active button styling for charts
        setActiveButton('charts');
    } catch (e) {
        console.error("Error setting default view:", e);
    }
}

// Setup view buttons with proper event listeners
function setupViewButtons() {
    try {
        // Remove onclick attributes to prevent conflicts
        document.getElementById('chartsButton').removeAttribute('onclick');
        document.getElementById('rankingButton').removeAttribute('onclick');
        document.getElementById('predictButton').removeAttribute('onclick');
        
        // Add proper event listeners
        document.getElementById('chartsButton').addEventListener('click', function() {
            toggleView('charts');
        });
        
        document.getElementById('rankingButton').addEventListener('click', function() {
            toggleView('ranking');
        });
        
        document.getElementById('predictButton').addEventListener('click', function() {
            toggleView('predict');
        });
        
        console.log("View buttons initialized with event listeners");
    } catch (e) {
        console.error("Error setting up view buttons:", e);
    }
}

// Updated function to toggle between different views
function toggleView(view) {
    console.log(`Toggling view to: ${view}`);
    
    try {
        // Get all view elements
        const chartsView = document.getElementById('chartsView');
        const rankingView = document.getElementById('rankingView');
        const predictView = document.getElementById('predictView');
        
        if (!chartsView || !rankingView || !predictView) {
            console.error("One or more view containers not found!");
            return;
        }
        
        // First, hide all views
        chartsView.classList.add('hidden');
        rankingView.classList.add('hidden');
        predictView.classList.add('hidden');
        
        // Set active button styling
        setActiveButton(view);
        
        // Show the selected view
        if (view === 'charts') {
            chartsView.classList.remove('hidden');
            // Resize charts after they become visible
            setTimeout(() => {
                if (typeof resizeTrendCharts === 'function') {
                    resizeTrendCharts();
                }
            }, 100);
        } 
        else if (view === 'ranking') {
            rankingView.classList.remove('hidden');
            // Update ranking tables
            if (typeof updateRankingTables === 'function') {
                updateRankingTables();
            }
        } 
        else if (view === 'predict') {
            predictView.classList.remove('hidden');
            // Initialize or update forecast if not already done
            if (typeof generateForecast === 'function') {
                setTimeout(() => generateForecast(), 100);
            }
        }
        
        console.log(`View toggled to: ${view}`);
    } catch (e) {
        console.error("Error toggling view:", e);
    }
}

// Initialize a single master event listener to ensure no conflicts
function initializeMasterEventListener() {
    // Remove any existing DOMContentLoaded listeners (if possible)
    if (window._dashboardInitialized) {
        console.log("Dashboard already initialized, skipping...");
        return;
    }
    
    // Set a flag to track initialization
    window._dashboardInitialized = true;
    
    // Add a new clean event listener
    document.addEventListener('DOMContentLoaded', function() {
        console.log("DOM fully loaded, running dashboard initialization...");
        
        // Run main initialization
        setTimeout(() => {
            initializeDashboard();
        }, 100);
    });
    
    // Also run initialization if DOM is already loaded
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        console.log("DOM already loaded, running immediate initialization...");
        setTimeout(() => {
            initializeDashboard();
        }, 100);
    }
}

// Run the initialization process
initializeMasterEventListener();

// Add window resize handler
window.addEventListener('resize', function() {
    try {
        if (document.getElementById('chartsView') && 
            !document.getElementById('chartsView').classList.contains('hidden') && 
            typeof resizeTrendCharts === 'function') {
            resizeTrendCharts();
        }
        
        if (window.modalChart && 
            document.getElementById('chartModal') && 
            !document.getElementById('chartModal').classList.contains('hidden')) {
            modalChart.resize();
        }
        
        if (document.getElementById('predictView') && 
            !document.getElementById('predictView').classList.contains('hidden') && 
            window.forecastChart) {
            forecastChart.resize();
        }
    } catch (e) {
        console.error("Error during resize handling:", e);
    }
});