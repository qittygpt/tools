<?php
/**
 * WP User Panel - Safe Inline Admin (For Your Own Site)
 * Fitur:
 * - Add user (bisa langsung administrator)
 * - Edit username, email, role
 * - Reset password (plaintext, via wp_set_password)
 * - Delete user
 *
 * Cara pakai:
 * - Taruh file ini di root WordPress (satu folder dengan wp-load.php)
 * - Ubah $panel_password di bawah
 * - Akses: https://domain.com/nama-file-ini.php
 * - Hapus file setelah selesai dipakai
 */

$panel_password = 'gaspanel123'; // <<< GANTI PASSWORD PANEL DI SINI
session_start();

/* ---------- Login protection ---------- */
if (!isset($_SESSION['wp_user_panel_logged'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['panel_password'])) {
        if (hash_equals($panel_password, $_POST['panel_password'])) {
            $_SESSION['wp_user_panel_logged'] = true;
            header('Location: ' . basename(__FILE__));
            exit;
        } else {
            echo '<div style="font-family:Arial;padding:40px;text-align:center;">
                    <h2>WP User Panel</h2>
                    <p style="color:#b00020;">Password panel salah.</p>
                    <a href="'.htmlspecialchars(basename(__FILE__),ENT_QUOTES,'UTF-8').'">Coba lagi</a>
                  </div>';
            exit;
        }
    }

    echo '<form method="post" style="font-family:Arial;padding:40px;text-align:center;">
            <h2>WP User Panel</h2>
            <p style="color:#555;margin-bottom:10px;">Masuk ke panel user (khusus pemilik situs).</p>
            <input type="password" name="panel_password" placeholder="Panel password"
                   style="padding:10px;width:260px;border-radius:6px;border:1px solid #ddd;">
            <br><br><button style="padding:9px 18px;border-radius:6px;border:none;background:#0f62fe;color:#fff;cursor:pointer;">
                Login
            </button>
          </form>';
    exit;
}

/* ---------- Bootstrap WP ---------- */
$wp_load = __DIR__ . '/wp-load.php';
if (!file_exists($wp_load)) {
    die('wp-load.php tidak ditemukan. Pastikan file ini diletakkan di root WordPress.');
}
require_once $wp_load;

global $wpdb;

/* Helpers */
function esc_html_ez($s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

$users_table    = $wpdb->users;
$usermeta_table = $wpdb->usermeta;
$cap_key        = $wpdb->prefix . 'capabilities';

$error  = null;
$notice = null;

/* ---------- Handle POST Actions ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];

    // ADD USER
    if ($action === 'add_user') {
        $login     = sanitize_user($_POST['user_login']);
        $email     = sanitize_email($_POST['user_email']);
        $pass_plain= $_POST['user_pass'] ?? '';
        $role      = $_POST['user_role'] ?? 'subscriber';

        if ($login === '' || $email === '' || $pass_plain === '') {
            $error = 'Isi semua field untuk menambah user.';
        } elseif (username_exists($login)) {
            $error = 'Username sudah dipakai.';
        } elseif (email_exists($email)) {
            $error = 'Email sudah dipakai.';
        } else {
            $uid = wp_create_user($login, $pass_plain, $email);
            if (!is_wp_error($uid)) {
                // set role via WP_User
                $user = new WP_User($uid);
                $user->set_role($role);
                $notice = "User berhasil ditambah (ID: {$uid}).";
            } else {
                $error = 'Gagal menambah user: ' . $uid->get_error_message();
            }
        }
    }

    // EDIT USER (username, email, role, optional new password)
    if ($action === 'edit_user') {
        $uid   = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;
        $login = sanitize_user($_POST['user_login']);
        $email = sanitize_email($_POST['user_email']);
        $role  = $_POST['user_role'] ?? 'subscriber';
        $newpw = $_POST['new_password'] ?? '';

        if ($uid <= 0) {
            $error = 'User ID tidak valid.';
        } elseif ($login === '' || $email === '') {
            $error = 'Username dan email tidak boleh kosong.';
        } else {
            // ambil data sekarang
            $user_obj = get_user_by('id', $uid);
            if (!$user_obj) {
                $error = 'User tidak ditemukan.';
            } else {
                // cek bentrok username/email dengan user lain
                $existing_login = get_user_by('login', $login);
                if ($existing_login && intval($existing_login->ID) !== $uid) {
                    $error = 'Username sudah digunakan user lain.';
                } else {
                    $existing_email = get_user_by('email', $email);
                    if ($existing_email && intval($existing_email->ID) !== $uid) {
                        $error = 'Email sudah digunakan user lain.';
                    }
                }

                if ($error === null) {
                    // update email via wp_update_user
                    $upd = wp_update_user([
                        'ID'         => $uid,
                        'user_email' => $email,
                    ]);

                    if (is_wp_error($upd)) {
                        $error = 'Gagal update email: ' . $upd->get_error_message();
                    } else {
                        // update username langsung ke table users (WP tidak menyediakan API resmi untuk ganti user_login)
                        if ($login !== $user_obj->user_login) {
                            $res = $wpdb->update(
                                $users_table,
                                ['user_login' => $login],
                                ['ID' => $uid],
                                ['%s'],
                                ['%d']
                            );
                            if ($res === false) {
                                $error = 'Gagal update username (DB error).';
                            }
                        }
                    }

                    // update role
                    if ($error === null) {
                        $user_obj = new WP_User($uid);
                        $user_obj->set_role($role);
                    }

                    // jika ada password baru, set dengan aman
                    if ($error === null && $newpw !== '') {
                        wp_set_password($newpw, $uid);
                    }

                    if ($error === null) {
                        $notice = 'User berhasil diperbarui.';
                    }
                }
            }
        }
    }

    // RESET PASSWORD ONLY
    if ($action === 'reset_pass') {
        $uid   = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;
        $newpw = $_POST['reset_password'] ?? '';
        if ($uid <= 0) {
            $error = 'User ID tidak valid.';
        } elseif ($newpw === '') {
            $error = 'Password baru tidak boleh kosong.';
        } else {
            wp_set_password($newpw, $uid);
            $notice = "Password user ID {$uid} berhasil di-reset.";
        }
    }

    // DELETE USER
    if ($action === 'delete_user') {
        $uid = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;
        if ($uid <= 0) {
            $error = 'User ID tidak valid.';
        } else {
            require_once ABSPATH . 'wp-admin/includes/user.php';
            $deleted = wp_delete_user($uid);
            if ($deleted) {
                $notice = "User ID {$uid} berhasil dihapus.";
            } else {
                $error = 'Gagal menghapus user.';
            }
        }
    }
}

/* ---------- Fetch users ---------- */
$users = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT u.ID, u.user_login, u.user_email, u.user_pass,
            (SELECT meta_value FROM {$usermeta_table}
             WHERE user_id = u.ID AND meta_key = %s LIMIT 1) AS role
         FROM {$users_table} u
         ORDER BY u.ID ASC",
        $cap_key
    )
);

/* ---------- Filter by search ---------- */
$q = trim($_GET['q'] ?? '');
$filtered_users = [];
if ($q === '') {
    $filtered_users = $users;
} else {
    $ql = strtolower($q);
    foreach ($users as $u) {
        if (
            strpos(strtolower($u->user_login), $ql) !== false ||
            strpos(strtolower($u->user_email), $ql) !== false
        ) {
            $filtered_users[] = $u;
        }
    }
}

/* ---------- Output UI ---------- */
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WP User Panel</title>
<style>
:root{
    --bg:#f6f7f9;--card:#fff;--muted:#6b7280;--accent:#0f62fe;
}
body{
    font-family:Inter,Arial,sans-serif;
    background:var(--bg);
    margin:24px;
    color:#111;
}
.container{max-width:1120px;margin:0 auto;}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.h1{font-size:20px;font-weight:600;}
.card{
    background:var(--card);
    padding:16px;
    border-radius:10px;
    box-shadow:0 6px 18px rgba(16,24,40,0.04);
    margin-bottom:16px;
}
.small{font-size:13px;color:var(--muted);}
.input,select,button,textarea{font-family:inherit;}
.input{
    padding:8px;border:1px solid #e6e9ee;border-radius:8px;width:100%;
}
.table{width:100%;border-collapse:collapse;}
.table th{
    background:#fbfcfd;text-align:left;padding:10px;
    border-bottom:1px solid #eef2f7;font-weight:600;font-size:13px;
}
.table td{
    padding:10px;border-bottom:1px solid #f3f5f8;vertical-align:top;font-size:13px;
}
.btn{padding:7px 10px;border-radius:8px;border:none;cursor:pointer;font-size:13px;}
.btn-primary{background:var(--accent);color:#fff;}
.btn-danger{background:#ef4444;color:#fff;}
.btn-muted{background:#f3f4f6;color:#111;}
.row-actions button{margin-right:6px;margin-top:4px;}
.role-tag{
    background:#eef2ff;padding:6px 8px;border-radius:6px;font-size:12px;display:inline-block;
}
.hash-small{
    font-size:11px;color:#555;max-width:360px;word-break:break-all;
}
.search{padding:8px;width:260px;border-radius:8px;border:1px solid #e6e9ee;}
.note{font-size:12px;color:#555;margin-top:6px;}
.edit-block{margin-top:8px;padding:8px;background:#fbfcff;border-radius:8px;}
.inline-input{padding:6px;border:1px solid #e6e9ee;border-radius:6px;width:100%;font-size:13px;}
.label{font-size:12px;color:#555;margin-bottom:2px;display:block;}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <div class="h1">WP User Panel</div>
            <div class="small">Mini panel untuk kelola user (gunakan hanya di situs sendiri, hapus file setelah selesai).</div>
        </div>
        <div>
            <form method="get" style="display:inline-block;">
                <input class="search" name="q" placeholder="Cari username / email"
                       value="<?= esc_html_ez($q) ?>">
            </form>
            <a href="<?= esc_html_ez(basename(__FILE__)) ?>" style="text-decoration:none;margin-left:6px;">
                <button class="btn btn-muted">Refresh</button>
            </a>
        </div>
    </div>

    <?php if ($error): ?>
        <div class="card" style="border-left:4px solid #ef4444;">
            <strong>Error:</strong> <?= esc_html_ez($error) ?>
        </div>
    <?php endif; ?>

    <?php if ($notice): ?>
        <div class="card" style="border-left:4px solid #16a34a;">
            <strong>OK:</strong> <?= esc_html_ez($notice) ?>
        </div>
    <?php endif; ?>

    <!-- Add User -->
    <div class="card" style="max-width:900px;">
        <form method="post">
            <input type="hidden" name="action" value="add_user">
            <div style="display:flex;gap:12px;flex-wrap:wrap;">
                <div style="flex:1;min-width:160px;">
                    <label class="label">Username</label>
                    <input class="input" name="user_login" required>
                </div>
                <div style="flex:1.3;min-width:200px;">
                    <label class="label">Email</label>
                    <input class="input" type="email" name="user_email" required>
                </div>
                <div style="flex:1;min-width:160px;">
                    <label class="label">Password</label>
                    <input class="input" name="user_pass" required>
                </div>
                <div style="width:180px;">
                    <label class="label">Role</label>
                    <select class="input" name="user_role">
                        <option value="administrator">administrator</option>
                        <option value="editor">editor</option>
                        <option value="author">author</option>
                        <option value="contributor">contributor</option>
                        <option value="subscriber" selected>subscriber</option>
                    </select>
                </div>
                <div style="align-self:flex-end;">
                    <button class="btn btn-primary">Add User</button>
                </div>
            </div>
            <div class="note">Untuk menambah admin, pilih role <strong>administrator</strong>. Pastikan password kuat.</div>
        </form>
    </div>

    <!-- Users table -->
    <div class="card">
        <table class="table" role="grid">
            <thead>
                <tr>
                    <th style="width:50px;">ID</th>
                    <th style="width:180px;">Username &amp; Email</th>
                    <th style="width:120px;">Role</th>
                    <th>Password Hash (view-only)</th>
                    <th style="width:220px;">Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php
            $roles_list = ['administrator','editor','author','contributor','subscriber'];
            foreach ($filtered_users as $u):
                $role_text = '-';
                if ($u->role) {
                    $r = @unserialize($u->role);
                    if (is_array($r)) {
                        $keys = array_keys($r);
                        if (!empty($keys)) $role_text = $keys[0];
                    }
                }
                $short_hash = substr($u->user_pass, 0, 40) . (strlen($u->user_pass) > 40 ? '…' : '');
            ?>
                <tr>
                    <td><?= esc_html_ez($u->ID) ?></td>
                    <td>
                        <div><strong><?= esc_html_ez($u->user_login) ?></strong></div>
                        <div class="small"><?= esc_html_ez($u->user_email) ?></div>

                        <!-- Inline edit block -->
                        <div class="edit-block">
                            <form method="post">
                                <input type="hidden" name="action" value="edit_user">
                                <input type="hidden" name="user_id" value="<?= esc_html_ez($u->ID) ?>">
                                <div style="display:flex;flex-wrap:wrap;gap:8px;">
                                    <div style="flex:1;min-width:130px;">
                                        <label class="label">Username</label>
                                        <input class="inline-input" name="user_login" value="<?= esc_html_ez($u->user_login) ?>">
                                    </div>
                                    <div style="flex:1.3;min-width:180px;">
                                        <label class="label">Email</label>
                                        <input class="inline-input" name="user_email" value="<?= esc_html_ez($u->user_email) ?>">
                                    </div>
                                    <div style="width:150px;">
                                        <label class="label">Role</label>
                                        <select class="inline-input" name="user_role">
                                            <?php foreach ($roles_list as $r): ?>
                                                <option value="<?= esc_html_ez($r) ?>" <?= ($role_text === $r ? 'selected' : '') ?>>
                                                    <?= esc_html_ez($r) ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div style="flex:1;min-width:180px;">
                                        <label class="label">New Password (optional)</label>
                                        <input class="inline-input" name="new_password" placeholder="Biarkan kosong jika tidak diubah">
                                    </div>
                                    <div style="align-self:flex-end;">
                                        <button class="btn btn-primary">Save</button>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </td>

                    <td>
                        <span class="role-tag"><?= esc_html_ez($role_text) ?></span>
                    </td>

                    <td>
                        <div class="hash-small" id="hash-<?= esc_html_ez($u->ID) ?>"><?= esc_html_ez($short_hash) ?></div>
                        <div class="small" style="margin-top:4px;">
                            Hash ini hanya untuk informasi (tidak bisa diedit di panel ini).
                        </div>
                    </td>

                    <td class="row-actions">
                        <!-- Reset password quick -->
                        <form method="post" onsubmit="return askResetPassword(event,this);" style="margin-bottom:4px;">
                            <input type="hidden" name="action" value="reset_pass">
                            <input type="hidden" name="user_id" value="<?= esc_html_ez($u->ID) ?>">
                            <input type="hidden" name="reset_password" value="">
                            <button type="submit" class="btn btn-muted">Reset Password…</button>
                        </form>

                        <!-- Delete user -->
                        <form method="post" onsubmit="return confirm('Hapus user ini?');">
                            <input type="hidden" name="action" value="delete_user">
                            <input type="hidden" name="user_id" value="<?= esc_html_ez($u->ID) ?>">
                            <button type="submit" class="btn btn-danger">Delete</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($filtered_users)): ?>
                <tr><td colspan="5" class="small">Tidak ada user yang cocok dengan pencarian.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <div class="small" style="margin-top:10px;">
        ⚠ Gunakan hanya di situs sendiri. Setelah selesai, <strong>hapus file panel ini dari server</strong>.
    </div>
</div>

<script>
function askResetPassword(e, form){
    e.preventDefault();
    var pw = prompt('Masukkan password baru (plaintext) untuk user ini:');
    if (!pw) return false;
    form.querySelector('input[name=reset_password]').value = pw;
    form.submit();
    return false;
}
</script>

</body>
</html>