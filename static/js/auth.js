const tg = window.Telegram.WebApp;

// Send authentication data to Django backend
fetch('/api/auth/verify/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ initData: tg.initData })
})
.then(response => response.json())
.then(data => {
    if (data.success) {
        window.location.href = '/api/home/';
    } else {
        alert("Authentication failed: " + data.error);
    }
});
