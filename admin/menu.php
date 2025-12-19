<?php
if (!defined('ABSPATH')) exit;

require_once IPINTEL_PATH . 'admin/dashboard.php';
require_once IPINTEL_PATH . 'admin/settings.php';

add_action('admin_menu', function () {
    $cap = 'manage_options';

    // Main menu
    add_menu_page(
        'IPIntel AI Firewall',
        'IPIntel AI',
        $cap,
        'ipintel-dashboard',
        'ipintel_render_dashboard',
        'dashicons-shield',  // <-- FIXED ICON
        70
    );

    // Dashboard submenu
    add_submenu_page(
        'ipintel-dashboard',
        'Dashboard',
        'Dashboard',
        $cap,
        'ipintel-dashboard',
        'ipintel_render_dashboard'
    );

    // Settings submenu
    add_submenu_page(
        'ipintel-dashboard',
        'Settings',
        'Settings',
        $cap,
        'ipintel-settings',
        'ipintel_render_settings_page'
    );
});



