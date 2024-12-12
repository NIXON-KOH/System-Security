let tabId;
//ai generated this shit idk wtf they doing but it works so i aint touching jack
function generateTabId() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) { 
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function initializeTab() {
    if (!localStorage.getItem('tabIds')) {
        localStorage.setItem('tabIds', '[]');
    }

    let tabIds = JSON.parse(localStorage.getItem('tabIds'));
    tabId = generateTabId();
    tabIds.push(tabId);
    localStorage.setItem('tabIds', JSON.stringify(tabIds));

    window.addEventListener('beforeunload', function() {
        let tabIds = JSON.parse(localStorage.getItem('tabIds'));
        let index = tabIds.indexOf(tabId);
        if (index > -1) {
            tabIds.splice(index, 1);
            localStorage.setItem('tabIds', JSON.stringify(tabIds));
        }
    });
}

function checkActiveTab() {
    fetch("/check_active_tab", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ tabId: tabId }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === "Invalid session" || data.status === "Session timed out") {
            alert("Your session has expired. Please log in again.");
            window.location.href = "{{ url_for('login') }}";
        } else if (data.status !== "Active tab") {
            showInactiveOverlay();
        } else {
            hideInactiveOverlay();
        }
    });
}

function showInactiveOverlay() {
    let overlay = document.getElementById('inactive-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'inactive-overlay';
        overlay.innerHTML = `
            <div id="inactive-message">
                <h2>DID YOU KNOW</h2>
                <p>in terms of male human and female Pokémon breeding, Vaporeon is the most compatible Pokémon for humans?</p>
                <button id="use-here-button" onclick="setActiveTab()">Damn</button>
            </div>
        `;
        document.body.appendChild(overlay);
    }
    overlay.style.display = 'flex';
}

function hideInactiveOverlay() {
    let overlay = document.getElementById('inactive-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

function setActiveTab() {
    fetch("/set_active_tab", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ tabId: tabId }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === "Tab set as active") {
            hideInactiveOverlay();
        }
    });
}

window.onload = function() {
    initializeTab();
    checkActiveTab();
    setInterval(checkActiveTab, 5000); 
};