<?php
/*
Plugin Name: IPIntel AI Firewall
Plugin URI: https://ipintel.ai/wordpess-plugin
Description: AI-powered IP reputation, bot detection, and automated protection for WordPress.
Version: 0.3.1
Author: IPIntel.ai
Author URI: https://ipintel.ai
License: GPLv2 or later
*/

if (!defined('ABSPATH')) exit;

if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool {
        return $needle !== '' && strpos($haystack, $needle) !== false;
    }
}




define('IPINTEL_VERSION', '0.3.1');

define('IPINTEL_PATH', plugin_dir_path(__FILE__));
define('IPINTEL_URL', plugin_dir_url(__FILE__));

if (!defined('IPINTEL_API_ENDPOINT')) {
    define('IPINTEL_API_ENDPOINT', 'https://api.ipintel.ai/ip.php');
}

/**
 * HARDENING AGAINST ACTION SCHEDULER EARLY CALLS
 */
add_filter('pre_option_action_scheduler_run_queue', '__return_false', 1);
add_filter('action_scheduler_pre_init', function ($val) {
    if (!did_action('init')) {
        return false;
    }
    return $val;
}, 1);

require_once IPINTEL_PATH . 'includes/class-core.php';
require_once IPINTEL_PATH . 'admin/menu.php';


/**
 * ACTIVATION: Only add options
 */
register_activation_hook(__FILE__, function () {

    add_option('ipintel_api_key', '');
    add_option('ipintel_mode', 'monitor');

    if (get_option('ipintel_firewall_enabled', null) === null) {
        add_option('ipintel_firewall_enabled', 1);
    }
    if (get_option('ipintel_challenge_threshold', null) === null) {
        add_option('ipintel_challenge_threshold', 60);
    }
    if (get_option('ipintel_block_threshold', null) === null) {
        add_option('ipintel_block_threshold', 180);
    }

    if (get_option('ipintel_challenge_theme', null) === null) {
        add_option('ipintel_challenge_theme', 'dark');
    }

    if (get_option('ipintel_block_theme', null) === null) {
        add_option('ipintel_block_theme', 'dark');
    }

    if (get_option('ipintel_challenge_duration', null) === null) {
        add_option('ipintel_challenge_duration', 10800);
    }
    
// Footer badge mode: off | dark | light
if (get_option('ipintel_footer_badge', null) === null) {
    add_option('ipintel_footer_badge', 'off');
}






});


/**
 * REGISTER CRON SAFELY (outside activation)
 */
add_action('init', function () {
    if (!wp_next_scheduled('ipintel_prune_cache')) {
        wp_schedule_event(time() + 300, 'hourly', 'ipintel_prune_cache');
    }
});




register_activation_hook(__FILE__, 'ipintel_install_htaccess_rules');
register_deactivation_hook(__FILE__, 'ipintel_remove_htaccess_rules');

/**
 * DEACTIVATION: Remove cron
 */
register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('ipintel_prune_cache');
});

add_action('ipintel_prune_cache', ['IPIntel_Core', 'cron_prune_cache']);


/**
 * ADMIN SCRIPTS
 */
add_action('admin_enqueue_scripts', function ($hook) {

    if (!function_exists('get_current_screen')) return;
    $screen = get_current_screen();
    if (!$screen || empty($screen->id)) return;

    $allowed_ids = [
        'toplevel_page_ipintel-dashboard',
        'ipintel-ai_page_ipintel-settings',
    ];

    if (!in_array($screen->id, $allowed_ids, true)) {
        return;
    }

    wp_enqueue_style(
        'ipintel-admin-css',
        IPINTEL_URL . 'assets/admin.css',
        [],
        IPINTEL_VERSION
    );

    wp_enqueue_script(
        'ipintel-deckgl',
        IPINTEL_URL . 'assets/deck.gl@8.8.19/dist.min.js',
        [],
        IPINTEL_VERSION,
        true
    );

    wp_enqueue_script(
        'ipintel-map',
        IPINTEL_URL . 'assets/ipintel-map.js',
        ['ipintel-deckgl'],
        IPINTEL_VERSION,
        true
    );

    wp_localize_script('ipintel-map', 'IPIntelMapData', [
        'worldUrl' => IPINTEL_URL . 'assets/custom.geo.json',
        'ajaxUrl'  => admin_url('admin-ajax.php'),
    ]);
});


add_action('plugins_loaded', ['IPIntel_Core', 'init'], 1);

add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    $settings_link = '<a href="' . admin_url('admin.php?page=ipintel-settings') . '">Settings</a>';
    $links[] = $settings_link;

    return $links;
});



  





add_filter('admin_body_class', function ($classes) {
    if (!function_exists('get_current_screen')) {
        return $classes;
    }

    $screen = get_current_screen();

    if ($screen && $screen->id === 'ipintel-dashboard_page_ipintel-settings') {
        $classes .= ' ipintel-settings-page ';
    }

    return $classes;
});



/**
 * Render IPIntel.ai footer badge
 */
add_action('wp_enqueue_scripts', function () {
    $mode = get_option('ipintel_footer_badge', 'off');
    if ($mode === 'off') return;


}, 20);




add_action('wp_footer', 'ipintel_render_badge', 100);

function ipintel_render_badge() {
    if (is_admin()) return;

    $mode = get_option('ipintel_footer_badge', 'off');
    if ($mode === 'off') return;

    $is_dark = ($mode === 'dark');

$parsed = wp_parse_url( home_url('/') );
$host   = isset($parsed['host']) ? $parsed['host'] : '';
$host = preg_replace('/[^a-z0-9\.\-]/i', '', (string)$host);

    $url = add_query_arg([
        'utm_source'   => 'wp-plugin',
        'utm_medium'   => 'footer-badge',
        'utm_campaign' => 'referral',
        'utm_content'  => $host,
    ], 'https://ipintel.ai/');

    $bg   = $is_dark ? '#05080d' : '#f6fbff';
    $fg   = $is_dark ? '#bfefff' : '#063247';
    $brd  = $is_dark ? 'rgba(0,255,255,0.35)' : 'rgba(0,180,210,0.35)';
    $glow = $is_dark ? '0 0 18px rgba(0,255,255,0.18)' : '0 0 12px rgba(0,180,210,0.12)';

    echo '<div class="ipintel-footer-badge-wrap" style="position:relative; z-index:9999; display:flex; justify-content:center; padding:0px 0 20px 0;">';
    echo '<a href="' . esc_url($url) . '" target="_blank" rel="nofollow noopener"
            style="
                display:inline-flex; align-items:center; gap:7px;
                padding:6px 12px 6px 8px;
                border-radius:999px;
                border:1px solid ' . esc_attr($brd) . ';
                background:' . esc_attr($bg) . ';
                box-shadow:' . esc_attr($glow) . ';
                text-decoration:none;
                color:' . esc_attr($fg) . ';
                font-family:\'Share Tech Mono\', monospace;
          
                line-height:1;
            " aria-label="Protected by IPIntel.ai">';


 $ipintel_allowed_svg = [
    'svg' => [
        'xmlns'   => true,
        'viewBox' => true,
        'width'   => true,
        'height'  => true,
        'fill'    => true,
        'class'   => true,
    ],
    'path' => [
        'd'    => true,
        'fill' => true,
    ],
];
   
   // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    echo '<span style="display:inline-flex;  align-items:center; justify-content:center;">' . ipintel_badge_logo_svg(). '</span>';
    echo '<span style="font-size:12px; white-space:nowrap;">Protected by <strong style="font-weight:700;">IPIntel.ai</strong></span>';
    echo '</a></div>';
}

function ipintel_badge_logo_svg() {
    // Inline SVG (scaled down). Keep it light-weight for footer.
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="20" height="20" aria-hidden="true" focusable="false">
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="blur"></feGaussianBlur>
            <feMerge>
              <feMergeNode in="blur"></feMergeNode>
              <feMergeNode in="SourceGraphic"></feMergeNode>
            </feMerge>
          </filter>
        </defs>
        <g stroke-linecap="round" stroke-linejoin="round" filter="url(#glow)">
        
     <polygon
  points="41,11 81,11 111,41 111,81 81,111 41,111 11,81 11,41"
  stroke="#000000"
  stroke-width="1"
  fill="none"
/>

<!--neon -->
<polygon
  points="40,10 80,10 110,40 110,80 80,110 40,110 10,80 10,40"
  stroke="#00FFFF"
  stroke-width="2"
  fill="none"
/>

               <rect x="41" y="41" width="40" height="40" stroke="#000000" stroke-width="1.5" fill="none" opacity="0.5"></rect>
          <rect x="40" y="40" width="40" height="40" stroke="#00FFFF" stroke-width="1.5" fill="none" opacity="1"></rect>

        <line x1="61" y1="11" x2="61" y2="41" stroke="#000000" stroke-width="1.2" opacity="0.5"></line>
          <line x1="61" y1="81" x2="61" y2="111" stroke="#000000" stroke-width="1.2" opacity="0.5"></line>
          <line x1="11" y1="61" x2="41" y2="61" stroke="#000000" stroke-width="1.2" opacity="0.5"></line>
          <line x1="81" y1="61" x2="111" y2="61" stroke="#000000" stroke-width="1.2" opacity="0.5"></line>
          
          <line x1="60" y1="10" x2="60" y2="40" stroke="#00FFFF" stroke-width="1.2" opacity="1"></line>
          <line x1="60" y1="80" x2="60" y2="110" stroke="#00FFFF" stroke-width="1.2" opacity="1"></line>
          <line x1="10" y1="60" x2="40" y2="60" stroke="#00FFFF" stroke-width="1.2" opacity="1"></line>
          <line x1="80" y1="60" x2="110" y2="60" stroke="#00FFFF" stroke-width="1.2" opacity="1"></line>
          <circle cx="60" cy="60" r="7" fill="#00FFFF" stroke="#FFFFFF" stroke-width="2"></circle>
        </g>
      </svg>';
}



function ipintel_get_htaccess_rules_lines(): array {
    return [
        '<IfModule LiteSpeed>',
        '',
        '    # IPIntel: challenge page — NEVER cache',
        '    RewriteCond %{QUERY_STRING} (^|&)ipintel_challenge=1(&|$)',
        '    RewriteRule .* - [E=Cache-Control:no-cache]',
        '',
        '    # IPIntel: challenge verify (admin-ajax)',
        '    RewriteCond %{REQUEST_URI} admin-ajax\\.php$',
        '    RewriteCond %{QUERY_STRING} (^|&)action=ipintel_challenge_verify(&|$)',
        '    RewriteRule .* - [E=Cache-Control:no-cache]',
        '',
        '    # IPIntel: one-shot verified bridge',
        '    RewriteCond %{QUERY_STRING} (^|&)ipintel_verified=1(&|$)',
        '    RewriteRule .* - [E=Cache-Control:no-cache]',
        '',
        '    # IPIntel: not verified yet → do not cache',
        '    RewriteCond %{HTTP_COOKIE} !ipintel_human_ok',
        '    RewriteRule .* - [E=Cache-Control:no-cache]',
        '',
        '</IfModule>',
        '',
    ];
}


function ipintel_install_htaccess_rules() {

    $htaccess = ABSPATH . '.htaccess';

    if ( ! function_exists( 'insert_with_markers' ) ) {
        require_once ABSPATH . 'wp-admin/includes/misc.php';
    }

    // If the file does not exist, attempt to create it safely.
    if ( ! file_exists( $htaccess ) ) {
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        global $wp_filesystem;
        if ( $wp_filesystem ) {
            $wp_filesystem->put_contents( $htaccess, '', FS_CHMOD_FILE );
        } else {
            // Could not create file; bail safely.
            return;
        }
    }

    $lines = ipintel_get_htaccess_rules_lines();

    // Official WP method for managing BEGIN/END blocks.
    insert_with_markers( $htaccess, 'IPINTEL FIREWALL', $lines );
}


function ipintel_remove_htaccess_rules() {

    $htaccess = ABSPATH . '.htaccess';

    if ( ! file_exists( $htaccess ) ) {
        return;
    }

    if ( ! function_exists( 'insert_with_markers' ) ) {
        require_once ABSPATH . 'wp-admin/includes/misc.php';
    }

    // Remove the block by writing empty lines for that marker.
    insert_with_markers( $htaccess, 'IPINTEL FIREWALL', [] );
}




