<?php
// --- KONFIGURASI DATABASE ---
$dbFile = 'database.sqlite';
try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL,
        display_name VARCHAR(100)
    )");

    $stmt = $pdo->query("SELECT COUNT(*) FROM users");
    if ($stmt->fetchColumn() == 0) {
        $users = [
            ['username' => 'admin', 'password' => 'admin123', 'role' => 'admin', 'display_name' => 'Administrator'],
            ['username' => 'user1', 'password' => 'password1', 'role' => 'user', 'display_name' => 'Asep Dinamo'],
            ['username' => 'user2', 'password' => 'password2', 'role' => 'user', 'display_name' => 'Ujang Dongkrak'],
        ];

        $insertStmt = $pdo->prepare("INSERT INTO users (username, password, role, display_name) VALUES (:username, :password, :role, :display_name)");
        foreach ($users as $user) {
            $insertStmt->execute([
                ':username' => $user['username'],
                ':password' => password_hash($user['password'], PASSWORD_DEFAULT),
                ':role' => $user['role'],
                ':display_name' => $user['display_name'],
            ]);
        }
    }
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}

// --- LOGIKA APLIKASI ---
session_start();

$allowedActions = ['home', 'profile', 'login', 'reset_password', 'debug', 'components', 'update_profile', 'logs', 'fetch_url', 'logout'];
$action = $_GET['action'] ?? 'home';
if (!in_array($action, $allowedActions, true)) {
    $action = 'home';
}

$message = '';
$error_message = '';
$content = '';
$user = null;
$profile_user = null;
$logs = [];

function currentUser(): ?array
{
    return $_SESSION['user'] ?? null;
}

function requireLogin(): void
{
    if (!currentUser()) {
        header('Location: ?action=login');
        exit;
    }
}

function currentUserIsAdmin(): bool
{
    $user = currentUser();
    return $user !== null && $user['role'] === 'admin';
}

function isPublicIp(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

if (!isset($_SESSION['csrf_token'])) {
    try {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    } catch (Exception $e) {
        $_SESSION['csrf_token'] = bin2hex(openssl_random_pseudo_bytes(32));
    }
}
$csrfToken = $_SESSION['csrf_token'];

function verifyCsrfToken(string $tokenFromRequest): bool
{
    return hash_equals($_SESSION['csrf_token'] ?? '', $tokenFromRequest);
}

// --- ROUTING BERDASARKAN ACTION ---
switch ($action) {
    case 'profile':
        requireLogin();
        $requestedId = isset($_GET['id']) ? (int) $_GET['id'] : (int) $_SESSION['user']['id'];
        if (!currentUserIsAdmin() && $requestedId !== (int) $_SESSION['user']['id']) {
            $requestedId = (int) $_SESSION['user']['id'];
        }

        $stmt = $pdo->prepare("SELECT id, username, role, display_name FROM users WHERE id = ?");
        $stmt->execute([$requestedId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user) {
            $message = "User not found.";
        }
        break;

    case 'login':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            $token = $_POST['csrf_token'] ?? '';

            if (!verifyCsrfToken($token)) {
                $message = 'Invalid session token. Please try again.';
                break;
            }

            $stmt = $pdo->prepare('SELECT id, username, password, role, display_name FROM users WHERE username = :username');
            $stmt->execute([':username' => $username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $authenticated = false;

                if (password_verify($password, $user['password'])) {
                    $authenticated = true;

                    if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
                        $newHash = password_hash($password, PASSWORD_DEFAULT);
                        $rehashStmt = $pdo->prepare('UPDATE users SET password = :password WHERE id = :id');
                        $rehashStmt->execute([':password' => $newHash, ':id' => $user['id']]);
                        $user['password'] = $newHash;
                    }
                } elseif (strlen($user['password']) === 32 && ctype_xdigit($user['password']) && hash_equals($user['password'], md5($password))) {
                    // Backward compatibility with legacy MD5 hashes
                    $authenticated = true;
                    $newHash = password_hash($password, PASSWORD_DEFAULT);
                    $rehashStmt = $pdo->prepare('UPDATE users SET password = :password WHERE id = :id');
                    $rehashStmt->execute([':password' => $newHash, ':id' => $user['id']]);
                    $user['password'] = $newHash;
                }

                if ($authenticated) {
                    session_regenerate_id(true);
                    try {
                        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    } catch (Exception $e) {
                        $_SESSION['csrf_token'] = bin2hex(openssl_random_pseudo_bytes(32));
                    }

                    unset($user['password']);
                    $_SESSION['user'] = $user;
                    header('Location: ?action=home');
                    exit;
                }
            }

            // Delay to slow down brute force attempts
            usleep(500000);
            $message = 'Login failed!';
        }
        break;

    case 'reset_password':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = $_POST['csrf_token'] ?? '';
            if (!verifyCsrfToken($token)) {
                $message = 'Invalid session token. Please try again.';
                break;
            }

            // Simulate sending reset email without leaking user existence
            $username = trim($_POST['username'] ?? '');
            if ($username !== '') {
                $message = 'Jika akun ditemukan, link reset password akan dikirimkan.';
            } else {
                $message = 'Silakan isi username.';
            }
        }
        break;

    case 'debug':
        requireLogin();
        if (isset($_GET['mode']) && $_GET['mode'] === 'true') {
            if (currentUserIsAdmin()) {
                $message = 'Mode debug dinonaktifkan demi keamanan.';
            } else {
                $message = 'Fitur debug hanya tersedia untuk admin.';
            }
        }
        break;

    case 'components':
        $component_info = [
            'name' => 'theme-loader-library',
            'version' => 'v2.0',
            'status' => 'Patched to enforce theme whitelist and prevent LFI',
        ];

        include 'new_library_v2.php';

        // Menangani submit form
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = $_POST['csrf_token'] ?? '';
            if (!verifyCsrfToken($token)) {
                $message = 'Invalid session token. Please try again.';
                break;
            }

            $selected_theme = trim($_POST['theme'] ?? '');
            echo "<div class='vulnerable-box'>";
            load_theme($selected_theme); // Memanggil fungsi dari library
            echo "</div>";
        }

        break;

    case 'update_profile':
        requireLogin();
        // Ambil data user yang sedang login untuk ditampilkan di form
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user']['id']]);
        $profile_user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = $_POST['csrf_token'] ?? '';
            if (!verifyCsrfToken($token)) {
                $message = 'Invalid session token. Please try again.';
                break;
            }

            $displayName = trim($_POST['display_name'] ?? '');
            $targetUserId = (int) $_SESSION['user']['id'];

            if ($displayName === '') {
                $message = 'Display name cannot be empty.';
                break;
            }

            $updateFields = ['display_name' => $displayName];
            $sql = 'UPDATE users SET display_name = :display_name';

            if (currentUserIsAdmin() && isset($_POST['role'])) {
                $newRole = $_POST['role'] === 'admin' ? 'admin' : 'user';
                $updateFields['role'] = $newRole;
                $sql .= ', role = :role';

                if (!empty($_POST['user_id']) && currentUserIsAdmin()) {
                    $targetUserId = (int) $_POST['user_id'];
                }
            }

            $sql .= ' WHERE id = :id';
            $updateFields['id'] = $targetUserId;

            $stmt = $pdo->prepare($sql);
            $stmt->execute($updateFields);

            if ($targetUserId === (int) $_SESSION['user']['id']) {
                $_SESSION['user']['display_name'] = $displayName;
                if (isset($updateFields['role'])) {
                    $_SESSION['user']['role'] = $updateFields['role'];
                }
            }

            $message = 'Profile updated successfully.';
        }
        break;

    case 'logs':
        $logs = [];
        break;

        case 'fetch_url':
        requireLogin();
        if (!currentUserIsAdmin()) {
            $error_message = 'Fitur ini hanya tersedia untuk admin.';
            break;
        }

        if (isset($_GET['url']) && !empty($_GET['url'])) {
            $url = trim($_GET['url']);

            if (filter_var($url, FILTER_VALIDATE_URL)) {
                $parsed = parse_url($url);
                $scheme = strtolower($parsed['scheme'] ?? '');

                if (in_array($scheme, ['http', 'https'], true)) {
                    $host = $parsed['host'] ?? '';

                    if ($host === '') {
                        $error_message = 'Host tidak ditemukan pada URL.';
                        break;
                    }

                    $resolvedIps = [];
                    if (filter_var($host, FILTER_VALIDATE_IP)) {
                        $resolvedIps[] = $host;
                    } else {
                        $dnsRecords = dns_get_record($host, DNS_A | DNS_AAAA);
                        if (!$dnsRecords) {
                            $error_message = 'Gagal melakukan resolusi DNS untuk host yang diberikan.';
                            break;
                        }

                        foreach ($dnsRecords as $record) {
                            if (isset($record['ip'])) {
                                $resolvedIps[] = $record['ip'];
                            } elseif (isset($record['ipv6'])) {
                                $resolvedIps[] = $record['ipv6'];
                            }
                        }
                    }

                    foreach ($resolvedIps as $ip) {
                        if (!isPublicIp($ip)) {
                            $error_message = 'Akses ke alamat internal atau privat diblokir.';
                            break 2;
                        }
                    }

                    $context = stream_context_create([
                        'http' => [
                            'timeout' => 3,
                            'follow_location' => 0,
                        ],
                        'https' => [
                            'timeout' => 3,
                            'follow_location' => 0,
                        ],
                    ]);

                    $content = @file_get_contents($url, false, $context);

                    if ($content === false) {
                        $error = error_get_last();
                        $error_message = "Gagal mengambil URL. Error: " . ($error['message'] ?? 'Permintaan tidak dapat diproses.');
                    } elseif (empty($content)) {
                        $error_message = 'URL berhasil diakses, tetapi tidak ada konten yang dikembalikan.';
                    }
                } else {
                    $error_message = 'Skema URL tidak diperbolehkan. Gunakan http atau https.';
                }
            } else {
                $error_message = 'Format URL tidak valid.';
            }
        }
        break;

    case 'logout':
        session_destroy();
        header('Location: ?action=login');
        exit;

    case 'home':
    default:
        break;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>OWASP Top 10 Lab</title>
    <style>
        body { font-family: sans-serif; }
        nav { background: #333; padding: 1rem; }
        nav a { color: white; margin-right: 1rem; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        .container { padding: 1rem; }
        .vulnerable-box { border: 1px solid #ccc; padding: 1rem; margin-top: 1rem; background-color: #f9f9f9; }
        .message { padding: 1rem; margin: 1rem 0; background: #eef; border: 1px solid #cce; }
        code { background: #eee; padding: 2px 5px; }
    </style>
</head>
<body>
    <nav>
        <a href="?action=home">Home</a>
        <?php if (!currentUser()): ?>
            <a href="?action=login">Login</a>
        <?php endif; ?>
        <a href="?action=profile&id=2">A01: Access Control</a>
        <a href="?action=reset_password">A04: Insecure Design</a>
        <a href="?action=debug">A05: Misconfiguration</a>
        <a href="?action=components">A06: Old Components</a>
        <a href="?action=update_profile">A08: Integrity Failures</a>
        <a href="?action=logs">A09: Logging Failures</a>
        <a href="?action=fetch_url">A10: SSRF</a>
        <?php if (currentUser()): ?>
            <a href="?action=logout">Logout (<?= htmlspecialchars(currentUser()['display_name']) ?>)</a>
        <?php endif; ?>
    </nav>
    <div class="container">
        <h1>OWASP Top 10 2021 Vulnerability Lab</h1>
        <?php if ($message): ?>
            <div class="message"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <?php switch ($action): case 'profile': ?>
            <h2>A01: Broken Access Control</h2>
            <p>Hanya pengguna yang berwenang yang dapat melihat profil ini. Administrator dapat memilih ID lain melalui URL.</p>
            <?php if ($user): ?>
                <div class="vulnerable-box">
                    <h3>Profile</h3>
                    <p><strong>ID:</strong> <?= $user['id'] ?></p>
                    <p><strong>Username:</strong> <?= htmlspecialchars($user['username']) ?></p>
                    <p><strong>Role:</strong> <?= htmlspecialchars($user['role']) ?></p>
                    <p><strong>Display Name:</strong> <?= htmlspecialchars($user['display_name']) ?></p>
                </div>
            <?php endif; ?>
        <?php break; case 'login': ?>
            <h2>Login (A03, A07, A02)</h2>
            <p>Autentikasi kini menggunakan prepared statement dan <code>password_hash()</code>. Serangan SQL Injection dan brute force diperlambat.</p>
            <form method="post">
                <label>Username: <input type="text" name="username"></label><br><br>
                <label>Password: <input type="password" name="password"></label><br><br>
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="submit" value="Login">
            </form>
        <?php break; case 'reset_password': ?>
            <h2>A04: Insecure Design</h2>
            <p>Formulir reset password kini memberikan pesan generik tanpa membocorkan apakah username valid.</p>
            <form method="post">
                <label>Username to Reset: <input type="text" name="username"></label><br><br>
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="submit" value="Reset Password">
            </form>
        <?php break; case 'debug': ?>
            <h2>A05: Security Misconfiguration</h2>
            <p>Halaman debug membutuhkan login admin dan tidak lagi menampilkan <code>phpinfo()</code>.</p>
        <?php break; case 'components': ?>

        <h2>A06: Vulnerable and Outdated Components</h2>
        <p>Komponen tema telah diperbarui untuk mencegah Local File Inclusion:</p>
        <ul>
            <li><strong>Name:</strong> <?= htmlspecialchars($component_info['name']) ?></li>
            <li><strong>Version:</strong> <?= htmlspecialchars($component_info['version']) ?></li>
            <li><strong>Status:</strong> <?= htmlspecialchars($component_info['status']) ?></li>
        </ul>
        
        <hr>
        
        <h3>Theme Loader Simulator</h3>
        <p>Loader kini memaksa penggunaan daftar tema yang diizinkan dan menolak input yang tidak dikenal.</p>
        
        <form method="post">
            <label>Select Theme: <input type="text" name="theme" placeholder="e.g., blue, green, default"></label>
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="submit" value="Load Theme">
        </form>
        
        <p>Library dipaksa selalu menggunakan versi terbaru untuk keamanan.</p>
        
  
        <?php break; case 'update_profile': ?>

            <h2>A08: Software and Data Integrity Failures</h2>
        <p>Form ini kini memvalidasi CSRF token dan membatasi perubahan role hanya untuk admin.</p>
        
        <?php if (isset($profile_user)): ?>
            <form method="post">
                <label>Display Name: <input type="text" name="display_name" value="<?= htmlspecialchars($profile_user['display_name']) ?>"></label><br><br>

                <?php if (currentUserIsAdmin()): ?>
                    <label>Role:
                        <select name="role">
                            <option value="user" <?= $profile_user['role'] === 'user' ? 'selected' : '' ?>>User</option>
                            <option value="admin" <?= $profile_user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                        </select>
                    </label><br><br>
                    <label>User ID (admin only): <input type="number" name="user_id" value="<?= htmlspecialchars($profile_user['id']) ?>" min="1"></label><br><br>
                <?php endif; ?>

                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="submit" value="Update Profile">
            </form>
            <?php endif; ?>
        <?php break; case 'logs': ?>
            <h2>A09: Security Logging and Monitoring Failures</h2>
            <p>Halaman ini seharusnya menampilkan log keamanan, tapi selalu kosong karena tidak ada logging yang diimplementasikan.</p>
            <pre><?= htmlspecialchars(implode("\n", $logs)) ?></pre>
        <?php break; case 'fetch_url': ?>

            <h2>A10: Server-Side Request Forgery (SSRF)</h2>
        <p>Hanya admin yang dapat menggunakan fitur ini dan server membatasi URL ke skema <code>http</code>/<code>https</code> publik.</p>
        
        <form method="get">
            <input type="hidden" name="action" value="fetch_url">
            <label>URL to Fetch: <input type="text" name="url" size="50" value="<?= htmlspecialchars($_GET['url'] ?? '') ?>"></label><br><br>
            <input type="submit" value="Fetch">
        </form>
        
        <?php if ($error_message): ?>
            <h3>Debug Information (Error Log):</h3>
            <div class="vulnerable-box" style="background-color: #ffdddd; border-color: #ff9999;">
                <p style="color: red;"><strong><?= htmlspecialchars($error_message) ?></strong></p>
            </div>
        <?php endif; ?>

        <?php if ($content): ?>
            <h3>Fetched Content:</h3>
            <div class="vulnerable-box">
                <pre><?= htmlspecialchars($content) ?></pre>
            </div>
        <?php endif; ?>

        <?php break; case 'home': default: ?>
            <h2>Selamat Datang di Lab OWASP Top 10!</h2>
            <p>Aplikasi ini sengaja dibuat rentan untuk tujuan pembelajaran. Gunakan menu di atas untuk menjelajahi setiap kerentanan.</p>
            <p>Untuk beberapa fitur, Anda perlu login terlebih dahulu.</p>
        <?php endswitch; ?>
    </div>
</body>
</html>