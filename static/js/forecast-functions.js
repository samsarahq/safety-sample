// Initialize forecast chart
let forecastChart = null;

// Function to update forecast period display
function updateForecastPeriod(value) {
    document.getElementById('forecast-period-value').textContent = value;
}

// Function to generate and display forecast
function generateForecast() {

    const metricSelect = document.getElementById('forecast-metric');
    const selectedMetric = metricSelect.value;
    const metricLabel = metricSelect.options[metricSelect.selectedIndex].text;
    
    const forecastPeriods = parseInt(document.getElementById('forecast-periods').value);
    
    // Generate forecast model using our module
    const forecastModel = window.SafetyForecasting.generateForecastModel(chartData, forecastPeriods);

    window.currentForecastModel = forecastModel;
    
    // Prepare chart data
    const series = [];
    const legendData = [];
    
    // Add historical and forecast series for each organization
    Object.keys(forecastModel).forEach(org => {
        if (org === 'Totals') return; // Skip totals row
        
        const metricData = forecastModel[org][selectedMetric];
        const historicalData = metricData.historical;
        const forecastData = metricData.forecast;
        
        // Add historical data series
        series.push({
            name: org + ' (Historical)',
            type: 'line',
            symbol: 'circle',
            symbolSize: 6,
            data: historicalData,
            lineStyle: {
                width: 3
            }
        });
        
        // Add forecast data series
        series.push({
            name: org + ' (Forecast)',
            type: 'line',
            symbol: 'circle',
            symbolSize: 6,
            data: forecastData,
            lineStyle: {
                type: 'dashed',
                width: 3
            },
            itemStyle: {
                opacity: 0.8
            }
        });
        
        legendData.push(org + ' (Historical)');
        legendData.push(org + ' (Forecast)');
    });
    
    // Render or update forecast chart
    const container = document.getElementById('forecastChartContainer');
    
    if (forecastChart) {
        forecastChart.dispose();
    }
    
    forecastChart = echarts.init(container);
    
    forecastChart.setOption({
        title: {
            text: `${metricLabel} Forecast`,
            left: 'center'
        },
        tooltip: {
            trigger: 'axis',
            formatter: function(params) {
                const date = params[0].data[0];
                let result = `<div>${date}</div>`;
                
                params.forEach(param => {
                    const isForecast = param.seriesName.includes('Forecast');
                    const marker = param.marker;
                    const name = isAnonymized ? anonymizeOrgName(param.seriesName) : param.seriesName;
                    const value = param.data[1];
                    
                    result += `<div style="margin-top:5px;">
                        ${marker} ${name}: ${value}
                        ${isForecast ? ' <span style="color:#ff9800">(Predicted)</span>' : ''}
                    </div>`;
                });
                
                return result;
            }
        },
        legend: {
            data: legendData,
            orient: 'vertical',
            right: 10,
            top: 20,
            type: 'scroll',
            formatter: function(name) {
                return isAnonymized ? anonymizeOrgName(name) : name;
            }
        },
        grid: {
            left: '3%',
            right: '20%',
            bottom: '3%',
            containLabel: true
        },
        xAxis: {
            type: 'category',
            boundaryGap: false,
            axisLabel: {
                formatter: function(value) {
                    return value.split('-').slice(0, 2).join('-'); // Show YYYY-MM format
                }
            },
            splitLine: {
                show: true,
                lineStyle: {
                    type: 'dashed'
                }
            }
        },
        yAxis: {
            type: 'value',
            splitLine: {
                lineStyle: {
                    type: 'dashed'
                }
            }
        },
        series: series,
        color: ['#1f77b4', '#aec7e8', '#ff7f0e', '#ffbb78', '#2ca02c', '#98df8a', 
                '#d62728', '#ff9896', '#9467bd', '#c5b0d5', '#8c564b', '#c49c94']
    });
    
    // Update growth insights
    updateGrowthInsights(forecastModel, selectedMetric);
    
    // Show concerning trends
    showConcerningTrends(forecastModel);
}

// Function to update growth insights
function updateGrowthInsights(forecastModel, selectedMetric) {
    const container = document.getElementById('growth-insights');
    container.innerHTML = '';
    
    // Get organizations with highest growth rates
    const orgs = Object.keys(forecastModel)
        .filter(org => org !== 'Totals')
        .sort((a, b) => {
            return parseFloat(forecastModel[b][selectedMetric].growth.monthly) - 
                   parseFloat(forecastModel[a][selectedMetric].growth.monthly);
        })
        .slice(0, 3); // Top 3 organizations
    
    orgs.forEach(org => {
        const growth = forecastModel[org][selectedMetric].growth;
        const trend = growth.trend;
        const value = growth.monthly;
        
        let colorClass = 'bg-gray-100';
        let arrowIcon = '→';
        
        if (trend === 'increasing') {
            colorClass = 'bg-red-100';
            arrowIcon = '↑';
        } else if (trend === 'decreasing') {
            colorClass = 'bg-green-100';
            arrowIcon = '↓';
        }
        
        const displayOrg = isAnonymized ? anonymizeOrgName(org) : org;
        
        const card = document.createElement('div');
        card.className = `p-4 rounded-lg ${colorClass}`;
        card.innerHTML = `
            <div class="text-lg font-semibold mb-1">${displayOrg}</div>
            <div class="text-2xl font-bold mb-1">
                ${arrowIcon} ${value}%
            </div>
            <div class="text-sm text-gray-600">Monthly growth rate</div>
        `;
        
        container.appendChild(card);
    });
}

// Function to show organizations with concerning trends
function showConcerningTrends(forecastModel) {
    const concerns = window.SafetyForecasting.identifyConcerningTrends(forecastModel);
    const container = document.getElementById('concerning-trends');
    
    if (concerns.length === 0) {
        document.getElementById('concerning-trends-container').classList.add('hidden');
        return;
    }
    
    document.getElementById('concerning-trends-container').classList.remove('hidden');
    
    // Create table
    let tableHtml = `
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Organization
                    </th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Metric
                    </th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Growth Rate
                    </th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Severity
                    </th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
    `;
    
    concerns.forEach(item => {
        const displayOrg = isAnonymized ? anonymizeOrgName(item.organization) : item.organization;
        const metricDisplay = item.metric.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
        
        let severityClass = 'bg-yellow-100 text-yellow-800';
        if (item.severity === 'high') {
            severityClass = 'bg-red-100 text-red-800';
        }
        
        tableHtml += `
            <tr>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                    ${displayOrg}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${metricDisplay}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    +${item.growth}%
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${severityClass}">
                        ${item.severity.toUpperCase()}
                    </span>
                </td>
            </tr>
        `;
    });
    
    tableHtml += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHtml;
}

// Initialize forecast when charts view is active
document.addEventListener('DOMContentLoaded', function() {
    // Add event listener to charts button to ensure forecast is generated
    // when charts view is active
    document.getElementById('chartsButton').addEventListener('click', function() {
        // Delay slightly to ensure charts are properly rendered first
        setTimeout(() => {
            generateForecast();
        }, 300);
    });
});