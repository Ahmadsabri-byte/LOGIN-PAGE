<?php
session_start();

// Jika sudah login, langsung ke dashboard
if (!empty($_SESSION['user'])) {
    header('Location: dashboard.php');
    exit;
}

// Data pengguna demo. Di aplikasi nyata, ambil dari database (PDO/MySQLi)
// dan simpan hash dari password_hash() di kolom password.
$users = [
    'admin' => password_hash('admin123', PASSWORD_DEFAULT),
    'budi'  => password_hash('budi123', PASSWORD_DEFAULT),
];

// Token CSRF
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

// Batasi percobaan login (5 kali, kunci 60 detik)
$_SESSION['attempts'] = $_SESSION['attempts'] ?? 0;
$_SESSION['locked_until'] = $_SESSION['locked_until'] ?? 0;

$error = '';
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $token    = $_POST['csrf'] ?? '';

    if (!hash_equals($_SESSION['csrf'], $token)) {
        $error = 'Permintaan tidak valid. Muat ulang halaman.';
    } elseif (time() < $_SESSION['locked_until']) {
        $sisa = $_SESSION['locked_until'] - time();
        $error = "Terlalu banyak percobaan. Coba lagi dalam {$sisa} detik.";
    } elseif ($username === '' || $password === '') {
        $error = 'Username dan password wajib diisi.';
    } elseif (isset($users[$username]) && password_verify($password, $users[$username])) {
        session_regenerate_id(true);
        $_SESSION['user'] = $username;
        $_SESSION['attempts'] = 0;
        header('Location: dashboard.php');
        exit;
    } else {
        $_SESSION['attempts']++;
        if ($_SESSION['attempts'] >= 5) {
            $_SESSION['locked_until'] = time() + 60;
            $_SESSION['attempts'] = 0;
        }
        $error = 'Username atau password salah.';
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #4f46e5, #7c3aed);
            padding: 16px;
        }
        .card {
            background: #fff;
            width: 100%;
            max-width: 380px;
            padding: 32px;
            border-radius: 14px;
            box-shadow: 0 20px 40px rgba(0,0,0,.2);
        }
        h1 { font-size: 24px; margin-bottom: 4px; color: #111827; }
        p.sub { color: #6b7280; margin-bottom: 24px; font-size: 14px; }
        label { display: block; font-size: 14px; margin-bottom: 6px; color: #374151; }
        input[type=text], input[type=password] {
            width: 100%;
            padding: 11px 12px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 15px;
            margin-bottom: 16px;
        }
        input:focus { outline: 2px solid #4f46e5; border-color: transparent; }
        button {
            width: 100%;
            padding: 12px;
            background: #4f46e5;
            color: #fff;
            border: 0;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
        }
        button:hover { background: #4338ca; }
        .error {
            background: #fee2e2;
            color: #991b1b;
            padding: 10px 12px;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 16px;
        }
        .hint { margin-top: 18px; font-size: 12px; color: #9ca3af; text-align: center; }
    </style>
</head>
<body>
    <form class="card" method="post" action="login.php" autocomplete="off">
        <h1>Selamat Datang</h1>
        <p class="sub">Silakan masuk ke akun Anda</p>

        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8') ?>">

        <label for="username">Username</label>
        <input type="text" id="username" name="username" required
               value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>">

        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>

        <button type="submit">Masuk</button>

        <p class="hint">Demo: admin / admin123</p>
    </form>
</body>
</html>

