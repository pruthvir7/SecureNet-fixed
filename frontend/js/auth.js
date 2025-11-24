/**
 * SecureNet Authentication Module
 * Handles login, registration, and session management
 */

// API Configuration
const API_BASE_URL = 'http://localhost:5001/api';

/**
 * Check if user is authenticated
 * @returns {boolean} Authentication status
 */
function isAuthenticated() {
    const token = localStorage.getItem('auth_token'); 
    if (!token) return false;
    
    // Check if token is expired
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        const expiryTime = payload.exp * 1000; // Convert to milliseconds
        return Date.now() < expiryTime;
    } catch (e) {
        return false;
    }
}

/**
 * Get current user from localStorage
 * @returns {Object|null} User object or null
 */
function getCurrentUser() {
    const userStr = localStorage.getItem('user');
    if (!userStr) return null;
    
    try {
        return JSON.parse(userStr);
    } catch (e) {
        return null;
    }
}

/**
 * Logout user
 */
function logout() {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user');
    window.location.href = 'login.html';
}

/**
 * Make authenticated API request
 * @param {string} endpoint - API endpoint
 * @param {Object} options - Fetch options
 * @returns {Promise} Response data
 */
async function authenticatedFetch(endpoint, options = {}) {
    const token = localStorage.getItem('auth_token'); 
    
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': token ? `Bearer ${token}` : ''
        }
    };
    
    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers
        }
    };
    
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, mergedOptions);
        
        // Handle unauthorized
        if (response.status === 401) {
            logout();
            throw new Error('Unauthorized');
        }
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }
        
        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Get user's geographic location via IP
 * @returns {Promise<Object>} Location data
 */
async function getGeographicLocation() {
    try {
        const response = await fetch('https://ipapi.co/json/');
        const data = await response.json();
        
        return {
            country: data.country_code || 'Unknown',
            country_name: data.country_name || 'Unknown',
            city: data.city || 'Unknown',
            region: data.region || 'Unknown',
            latitude: data.latitude || 0,
            longitude: data.longitude || 0,
            ip: data.ip || '0.0.0.0',
            asn: data.asn ? data.asn.replace('AS', '') : '0',
            org: data.org || 'Unknown'
        };
    } catch (error) {
        console.error('Geolocation error:', error);
        return {
            country: 'Unknown',
            country_name: 'Unknown',
            city: 'Unknown',
            region: 'Unknown',
            latitude: 0,
            longitude: 0,
            ip: '0.0.0.0',
            asn: '0',
            org: 'Unknown'
        };
    }
}

/**
 * Display notification
 * @param {string} message - Notification message
 * @param {string} type - Notification type (success, error, warning, info)
 */
function showNotification(message, type = 'info') {
    // Check if notification container exists
    let container = document.getElementById('notification-container');
    
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            display: flex;
            flex-direction: column;
            gap: 10px;
        `;
        document.body.appendChild(container);
    }
    
    // Create notification
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.style.cssText = `
        background: white;
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        display: flex;
        align-items: center;
        gap: 0.75rem;
        min-width: 300px;
        animation: slideIn 0.3s ease-out;
    `;
    
    // Icon based on type
    const icons = {
        success: '<i class="fas fa-check-circle" style="color: #10b981; font-size: 1.25rem;"></i>',
        error: '<i class="fas fa-exclamation-circle" style="color: #ef4444; font-size: 1.25rem;"></i>',
        warning: '<i class="fas fa-exclamation-triangle" style="color: #f59e0b; font-size: 1.25rem;"></i>',
        info: '<i class="fas fa-info-circle" style="color: #3b82f6; font-size: 1.25rem;"></i>'
    };
    
    notification.innerHTML = `
        ${icons[type]}
        <span style="flex: 1;">${message}</span>
        <button onclick="this.parentElement.remove()" style="background: none; border: none; cursor: pointer; color: #9ca3af;">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    container.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Add animations
if (!document.getElementById('notification-animations')) {
    const style = document.createElement('style');
    style.id = 'notification-animations';
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(400px);
                opacity: 0;
            }
        }
    `;
    document.head.appendChild(style);
}

/**
 * Format timestamp to readable date
 * @param {string} timestamp - ISO timestamp
 * @returns {string} Formatted date
 */
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    
    return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric' 
    });
}

/**
 * Protect page - redirect if not authenticated
 */
function protectPage() {
    if (!isAuthenticated()) {
        window.location.href = 'login.html';
    }
}

// Run on page load
document.addEventListener('DOMContentLoaded', function() {
    // Check if current page requires authentication
    if (window.location.pathname.includes('dashboard') || 
        window.location.pathname.includes('admin')) {
        protectPage();
    }
    
    // Redirect to dashboard if already logged in on auth pages
    if ((window.location.pathname.includes('login') || 
         window.location.pathname.includes('register')) && 
        isAuthenticated()) {
        window.location.href = 'dashboard.html';
    }
});

// Export functions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        isAuthenticated,
        getCurrentUser,
        logout,
        authenticatedFetch,
        getGeographicLocation,
        showNotification,
        formatTimestamp,
        protectPage
    };
}
