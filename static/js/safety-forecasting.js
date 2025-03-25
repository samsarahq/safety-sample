/**
 * Safety Data Forecasting Module
 * 
 * This module provides forecasting capabilities for the safety data dashboard.
 * It's designed to work with the dashboard charts and data structures.
 */

// Create a namespace for our forecasting functions to avoid global scope pollution
window.SafetyForecasting = (function() {
    // Private variables and functions
    
    /**
     * Apply linear regression to the input data points
     * @param {Array} data - Array of [x, y] points
     * @returns {Object} Regression parameters
     */
    function linearRegression(data) {
        let sumX = 0;
        let sumY = 0;
        let sumXY = 0;
        let sumXX = 0;
        const n = data.length;
        
        data.forEach(point => {
            const [x, y] = point;
            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumXX += x * x;
        });
        
        const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
        const intercept = (sumY - slope * sumX) / n;
        
        return { slope, intercept };
    }
    
    /**
     * Calculate forecast values based on historical data
     * @param {Array} data - Array of [date, value] data points
     * @param {Number} periods - Number of periods to forecast
     * @returns {Object} Forecast data
     */
    function calculateForecast(data, periods) {
        // Need at least 3 data points for meaningful forecast
        if (data.length < 3) {
            return {
                historical: data,
                forecast: [],
                growth: { monthly: 0, trend: 'stable' }
            };
        }
        
        // Convert dates to numerical x values (0, 1, 2...)
        const numericalData = data.map((point, index) => [index, point[1]]);
        
        // Apply linear regression to get trend
        const { slope, intercept } = linearRegression(numericalData);
        
        // Calculate growth percentage (monthly)
        const firstValue = data[0][1];
        const lastValue = data[data.length - 1][1];
        const growthRate = firstValue > 0 ? 
            ((lastValue - firstValue) / firstValue) * 100 / (data.length - 1) : 0;
        
        let trend = 'stable';
        if (growthRate > 5) trend = 'increasing';
        else if (growthRate < -5) trend = 'decreasing';
        
        // Generate forecast data points
        const forecast = [];
        const lastDate = new Date(data[data.length - 1][0]);
        
        for (let i = 1; i <= periods; i++) {
            const forecastX = numericalData.length - 1 + i;
            const forecastY = Math.max(0, slope * forecastX + intercept); // Prevent negative values
            
            // Calculate new date by adding months
            const forecastDate = new Date(lastDate);
            forecastDate.setMonth(forecastDate.getMonth() + i);
            
            // Format date as YYYY-MM-DD
            const dateStr = forecastDate.toISOString().split('T')[0];
            forecast.push([dateStr, forecastY]);
        }
        
        return {
            historical: data,
            forecast: forecast,
            growth: {
                monthly: Math.round(growthRate * 10) / 10, // Round to 1 decimal place
                trend: trend
            }
        };
    }
    
    /**
     * Generate a forecast model for all organizations and metrics
     * @param {Array} data - The dashboard data array
     * @param {Number} periods - Number of periods to forecast
     * @returns {Object} Complete forecast model
     */
    function generateForecastModel(data, periods) {
        // Organization-based grouping
        const orgData = {};
        
        // Process each data row
        data.forEach(row => {
            const org = row.org_name;
            const month = row.report_month.split(' ')[0]; // Get just the date part
            
            if (!orgData[org]) {
                orgData[org] = {
                    months: [],
                    safetyEvents: [],
                    crashEvents: [],
                    reviewEvents: [],
                    totalDistance: [],
                    accidentsRatio: []
                };
            }
            
            // Store data for each metric
            orgData[org].months.push(month);
            orgData[org].safetyEvents.push([month, row.total_safety_events]);
            orgData[org].crashEvents.push([month, row.crash_events]);
            orgData[org].reviewEvents.push([month, row.safety_events_needing_review]);
            orgData[org].totalDistance.push([month, row.total_distance_km]);
            orgData[org].accidentsRatio.push([month, row.accidents_ratio_km]);
        });
        
        // Generate forecast model for each org and metric
        const forecastModel = {};
        
        Object.keys(orgData).forEach(org => {
            forecastModel[org] = {
                safetyEvents: calculateForecast(orgData[org].safetyEvents, periods),
                crashEvents: calculateForecast(orgData[org].crashEvents, periods),
                reviewEvents: calculateForecast(orgData[org].reviewEvents, periods),
                totalDistance: calculateForecast(orgData[org].totalDistance, periods),
                accidentsRatio: calculateForecast(orgData[org].accidentsRatio, periods)
            };
        });
        
        return forecastModel;
    }
    
    /**
     * Identify organizations with concerning trends
     * @param {Object} forecastModel - The forecast model
     * @returns {Array} Array of concerning trends
     */
    function identifyConcerningTrends(forecastModel) {
        const concerns = [];
        
        Object.keys(forecastModel).forEach(org => {
            if (org === 'Totals') return; // Skip totals
            
            // Check each metric
            [
                { key: 'safetyEvents', name: 'Safety Events', threshold: 10 },
                { key: 'crashEvents', name: 'Crash Events', threshold: 5 },
                { key: 'reviewEvents', name: 'Review Events', threshold: 15 },
                { key: 'accidentsRatio', name: 'Accidents Ratio', threshold: 8 }
            ].forEach(metric => {
                const data = forecastModel[org][metric.key];
                const growth = data.growth.monthly;
                
                // Only include if growth is positive and above threshold
                if (growth > metric.threshold) {
                    let severity = 'medium';
                    if (growth > metric.threshold * 2) severity = 'high';
                    
                    concerns.push({
                        organization: org,
                        metric: metric.name,
                        growth: Math.round(growth * 10) / 10,
                        severity: severity
                    });
                }
            });
        });
        
        // Sort by severity (high to low) and then by growth (high to low)
        concerns.sort((a, b) => {
            if (a.severity === b.severity) {
                return b.growth - a.growth;
            }
            return a.severity === 'high' ? -1 : 1;
        });
        
        return concerns;
    }
    
    // Public API
    return {
        generateForecastModel: generateForecastModel,
        identifyConcerningTrends: identifyConcerningTrends
    };
})();

// Make sure DOM is fully loaded before initializing anything
document.addEventListener('DOMContentLoaded', function() {
    console.log("Safety forecasting module loaded");
    
    // Initialize forecast chart container if it exists
    const forecastContainer = document.getElementById('forecastChartContainer');
    if (forecastContainer) {
        console.log("Forecast container found, initializing chart...");
        forecastChart = echarts.init(forecastContainer);
    }
});