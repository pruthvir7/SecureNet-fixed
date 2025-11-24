/**
 * Keystroke Dynamics Capture
 * Captures typing patterns for behavioral biometrics
 */

let keystrokeTimings = [];
let lastKeyTime = null;

/**
 * Reset keystroke capture data
 */
function resetKeystrokeCapture() {
    keystrokeTimings = [];
    lastKeyTime = null;
    console.log('Keystroke capture reset');
}

/**
 * Initialize keystroke capture on an input element
 * @param {HTMLElement} inputElement - The input field to monitor
 */
function initKeystrokeCapture(inputElement) {
    if (!inputElement) {
        console.error('No input element provided for keystroke capture');
        return;
    }
    
    // Remove existing listeners to prevent duplicates
    inputElement.removeEventListener('keydown', captureKeystroke);
    inputElement.removeEventListener('keyup', captureKeystroke);
    
    // Reset data
    resetKeystrokeCapture();
    
    // Add fresh listeners
    inputElement.addEventListener('keydown', captureKeystroke);
    
    console.log('Keystroke capture initialized');
}

/**
 * Capture individual keystroke timing
 * @param {KeyboardEvent} event - The keyboard event
 */
function captureKeystroke(event) {
    if (event.type === 'keydown') {
        const currentTime = Date.now();
        
        // Calculate time difference from last keystroke
        if (lastKeyTime !== null) {
            const timeDiff = currentTime - lastKeyTime;
            keystrokeTimings.push(timeDiff);
        }
        
        lastKeyTime = currentTime;
    }
}

/**
 * Get captured keystroke timings
 * @returns {Array<number>} Array of timing values
 */
function getKeystrokeTimings() {
    if (keystrokeTimings.length === 0) {
        console.warn('No keystroke data captured, using default');
        return [120]; // Default timing if no data
    }
    
    console.log(`Captured ${keystrokeTimings.length} keystroke timings:`, keystrokeTimings);
    return keystrokeTimings;
}

/**
 * Calculate keystroke statistics
 * @returns {Object} Statistics about typing pattern
 */
function getKeystrokeStats() {
    if (keystrokeTimings.length === 0) {
        return {
            count: 0,
            average: 0,
            min: 0,
            max: 0,
            stdDev: 0
        };
    }
    
    const sum = keystrokeTimings.reduce((a, b) => a + b, 0);
    const avg = sum / keystrokeTimings.length;
    const variance = keystrokeTimings.reduce((sq, n) => sq + Math.pow(n - avg, 2), 0) / keystrokeTimings.length;
    const stdDev = Math.sqrt(variance);
    
    return {
        count: keystrokeTimings.length,
        average: avg.toFixed(2),
        min: Math.min(...keystrokeTimings),
        max: Math.max(...keystrokeTimings),
        stdDev: stdDev.toFixed(2)
    };
}
