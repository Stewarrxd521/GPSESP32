<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GPS Tracker | Login</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body class="centered">
  <div class="card">
    <h1>Acceso al monitoreo</h1>
    <p class="muted">GPS en tiempo real por MQTT</p>
    <form id="loginForm">
      <label>Usuario</label>
      <input name="username" autocomplete="username" required>
      <label>Contraseña</label>
      <input name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Entrar</button>
    </form>
    <div id="msg" class="msg"></div>
  </div>
  <script>
    const form = document.getElementById('loginForm');
    const msg = document.getElementById('msg');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      msg.textContent = 'Ingresando...';
      const formData = new FormData(form);
      const res = await fetch('/api/login', { method: 'POST', body: formData });
      const data = await res.json();
      if (!res.ok) {
        msg.textContent = data.detail || 'Error';
        return;
      }
      localStorage.setItem('token', data.access_token);
      window.location.href = '/app';
    });
  </script>
</body>
</html>
