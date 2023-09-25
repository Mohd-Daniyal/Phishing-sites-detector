const notification = document.getElementById('notification');

function updateNotification(isPhishing) {
    if (isPhishing === "Safe") {
        notification.classList.remove("phishing"); 
        notification.classList.add("safe");
        notification.innerText = 'This URL is safe.';
    } else {
        notification.classList.remove("safe"); 
        notification.classList.add("phishing"); 
        notification.innerText = 'Warning: This URL may be a phishing site. Proceed with caution!';
    }
}

updateNotification(isPhishing);
