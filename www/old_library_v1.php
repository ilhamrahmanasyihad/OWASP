<?php
// old_library_v1.php
// Simulasi library lama yang memiliki kerentanan Local File Inclusion (LFI)

function load_theme($theme_name) {
    $allowed_themes = ['blue', 'green', 'default'];

    $normalized = strtolower(trim($theme_name));
    if (substr($normalized, -4) === '.php') {
        $normalized = substr($normalized, 0, -4);
    }

    if (in_array($normalized, $allowed_themes, true)) {
        $theme_file = __DIR__ . '/themes/' . $normalized . '.php';
        include $theme_file;
        return;
    }

    include __DIR__ . '/themes/default.php';
}
?>