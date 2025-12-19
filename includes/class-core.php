<?php
if (!defined('ABSPATH')) exit;

class IPIntel_Core
{
    /**
     * Bootstrap hooks
     */
    public static function init()
    {
    
    
    add_action('parse_request', function () {

// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$ipintel_verified = filter_input(
    INPUT_GET,
    'ipintel_verified',
    FILTER_SANITIZE_FULL_SPECIAL_CHARS
);


if (!$ipintel_verified) {
    return;
}

    $clean_url = remove_query_arg([
        'ipintel_verified',
        'ipintel_challenge',
        'target'
    ]);

    wp_safe_redirect($clean_url, 302);
    exit;

}, 0);



    
    add_filter('redirect_canonical', function ($redirect_url, $requested_url) {
    
    
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
if (isset($_GET['ipintel_challenge']) || isset($_GET['ipintel_verified'])) {
    return false;
}

    return $redirect_url;
}, 10, 2);



        // Firewall + challenge render on front-end
     add_action('template_redirect', [__CLASS__, 'maybe_render_challenge_page'], 0);
	add_action('template_redirect', [__CLASS__, 'maybe_firewall_check'], 5);


        // Threat map (admin ajax)
        add_action('wp_ajax_ipintel_threatmap', [__CLASS__, 'ajax_threatmap']);
        add_action('wp_ajax_nopriv_ipintel_threatmap', [__CLASS__, 'ajax_threatmap']);

        // Challenge verification
        add_action('wp_ajax_nopriv_ipintel_challenge_verify', [__CLASS__, 'ajax_challenge_verify']);
        add_action('wp_ajax_ipintel_challenge_verify', ['IPIntel_Core', 'ajax_challenge_verify']);

        // Threat stats for dashboard
        add_action('wp_ajax_ipintel_threat_stats', [__CLASS__, 'ajax_threat_stats']);
	add_action('wp_ajax_ipintel_map_points', [__CLASS__, 'ajax_map_points']);

add_action('send_headers', function () {

    if (is_admin()) return;

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

});

    }

    /**
     * Main firewall decision logic
     */
    public static function maybe_firewall_check()
    {
    

   $uri = isset($_SERVER['REQUEST_URI'])
    ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) )
    : '';


    // 1) NEVER firewall static assets
    if (preg_match('~\.(css|js|png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|eot|map)$~i', $uri)) {
        return;
    }



    // 3) Challenge page itself must NOT be firewalled
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    if (isset($_GET['ipintel_challenge'])) {
        return;
    }

    // 4) AJAX / API bypass
    if (
        (defined('DOING_AJAX') && DOING_AJAX) ||
        str_contains($uri, 'admin-ajax.php') ||
        str_contains($uri, 'wp-json')
    ) {
        return;
    }

    // 5) Admin / cron / cli bypass
    if (is_admin()) return;
    if (defined('DOING_CRON') && DOING_CRON) return;
    if (defined('WP_CLI') && WP_CLI) return;
    if (current_user_can('manage_options')) return;


        $ip = self::get_client_ip();
        if (!$ip) return;
        

        // Firewall enabled (kill switch)
        $firewall_enabled = get_option('ipintel_kill_switch', 'off') === 'on';

        // Thresholds (1–250)
        $challenge_threshold = (int) get_option('ipintel_challenge_threshold', 60);
        $block_threshold     = (int) get_option('ipintel_block_threshold', 180);

        if ($challenge_threshold < 1)  $challenge_threshold = 1;
        if ($block_threshold < 1)      $block_threshold = 1;
        if ($challenge_threshold > 250) $challenge_threshold = 250;
        if ($block_threshold > 250)     $block_threshold = 250;

        // Ensure block >= challenge
        if ($block_threshold < $challenge_threshold) {
            $block_threshold = $challenge_threshold;
        }

        // Request metadata
$uri = isset($_SERVER['REQUEST_URI'])
    ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI']))
    : '';

$method = isset($_SERVER['REQUEST_METHOD'])
    ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))
    : '';

$ua = isset($_SERVER['HTTP_USER_AGENT'])
    ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']))
    : '';


        $whitelisted = self::is_whitelisted_ip($ip) ? 1 : 0;

        $risk       = null;
        $threat     = null;
        $confidence = null;
        $country    = '';
        $decision   = 'allow';
        $cache_hit  = 0;
        $api_data   = null;

        // 1) Whitelist → always allow, no API call
        if ($whitelisted) {
            self::log_request([
                'ts'           => time(),
                'ip'           => $ip,
                'country'      => $country,
                'method'       => $method,
                'uri'          => $uri,
                'ua'           => $ua,
                'risk'         => $risk,
                'threat'       => $threat,
                'confidence'   => $confidence,
                'decision'     => 'allow',
                'whitelisted'  => 1,
                'blacklisted'  => 0,
                'cache'        => 0,
                'fw_enabled'   => $firewall_enabled ? 1 : 0,
                'api_response' => $api_data,
            ]);
            
                        // Threat map log
            self::maybe_log_threat_event($ip, $api_data, $decision);
            
            return;
        }

        // 2) Blacklist → hard block, no API call
        if (self::is_blacklisted_ip($ip)) {
            self::log_request([
                'ts'           => time(),
                'ip'           => $ip,
                'country'      => '',
                'method'       => $method,
                'uri'          => $uri,
                'ua'           => $ua,
                'risk'         => null,
                'threat'       => null,
                'confidence'   => null,
                'decision'     => 'block',
                'whitelisted'  => 0,
                'blacklisted'  => 1,
                'cache'        => 0,
                'fw_enabled'   => 1,
                'api_response' => null,
            ]);


            // Threat map log
            self::maybe_log_threat_event($ip, $api_data, $decision);
            
            self::render_block_page($ip, 0, []);
            exit;
        }

        // 3) If firewall is disabled or missing API key → allow, just log
        $api_key = get_option('ipintel_api_key', '');
        if (!$firewall_enabled || !$api_key) {
            self::log_request([
                'ts'           => time(),
                'ip'           => $ip,
                'country'      => $country,
                'method'       => $method,
                'uri'          => $uri,
                'ua'           => $ua,
                'risk'         => $risk,
                'threat'       => $threat,
                'confidence'   => $confidence,
                'decision'     => 'allow',
                'whitelisted'  => 0,
                'blacklisted'  => 0,
                'cache'        => 0,
                'fw_enabled'   => $firewall_enabled ? 1 : 0,
                'api_response' => $api_data,
            ]);
            
                        // Threat map log
            self::maybe_log_threat_event($ip, $api_data, $decision);
            
            
            return;
        }

        // 4) Firewall enabled → try cache
        $cache_entry = self::get_ip_cache($ip);
        if (is_array($cache_entry)) {
            $cache_hit  = 1;
            $risk       = isset($cache_entry['risk'])       ? (float) $cache_entry['risk']       : null;
            $threat     = isset($cache_entry['threat'])     ? (int)   $cache_entry['threat']     : null;
            $confidence = isset($cache_entry['confidence']) ? (int)   $cache_entry['confidence'] : null;
            $country    = isset($cache_entry['country'])    ? (string)$cache_entry['country']    : '';

            // Decision from cache + current thresholds, but human cookie bypass
            if (self::has_valid_human_cookie()) {
                $decision = 'allow';
            } else {
                if ($risk >= $block_threshold) {
                    $decision = 'block';
                } elseif ($risk >= $challenge_threshold) {
                    $decision = 'challenge';
                } else {
                    $decision = 'allow';
                }
            }

            if (!empty($cache_entry['api_json'])) {
                $decoded = json_decode($cache_entry['api_json'], true);
                if (is_array($decoded)) {
                    $api_data = $decoded;
                }
            }
        } else {
            // 5) Cache miss → real API lookup
            $api_data = self::lookup($ip);

            if (!is_array($api_data) || isset($api_data['error'])) {
                // If we cannot score IP, allow but log
                self::log_request([
                    'ts'           => time(),
                    'ip'           => $ip,
                    'country'      => '',
                    'method'       => $method,
                    'uri'          => $uri,
                    'ua'           => $ua,
                    'risk'         => null,
                    'threat'       => null,
                    'confidence'   => null,
                    'decision'     => 'allow',
                    'whitelisted'  => 0,
                    'blacklisted'  => 0,
                    'cache'        => 0,
                    'fw_enabled'   => 1,
                    'api_response' => $api_data,
                ]);
                
                
                            // Threat map log
            self::maybe_log_threat_event($ip, $api_data, $decision);
            
            
             //   error_log("error lookup: ".$api_data['error']);
                return;
            }

            // Extract threat/confidence/country from API
            list($threat, $confidence) = self::extract_threat_and_confidence($api_data);

            if (!empty($api_data['country_code'])) {
                $country = (string) $api_data['country_code'];
            } elseif (!empty($api_data['country'])) {
                $country = (string) $api_data['country'];
            }

            // Risk 0–250
            $risk = self::compute_risk($threat, $confidence);

            if (self::has_valid_human_cookie()) {
                $decision = 'allow';
            } else {
                if ($risk >= $block_threshold) {
                    $decision = 'block';
                } elseif ($risk >= $challenge_threshold) {
                    $decision = 'challenge';
                } else {
                    $decision = 'allow';
                }
            }

            // Cache IP
            $entry = [
                'ip'          => $ip,
                'risk'        => $risk,
                'threat'      => $threat,
                'confidence'  => $confidence,
                'country'     => $country,
                'whitelisted' => 0,
                'decision'    => $decision,
                'api_json'    => json_encode($api_data),
                'ts'          => time(),
            ];
            self::save_ip_cache($ip, $entry);

            // Threat map log
            self::maybe_log_threat_event($ip, $api_data, $decision);

        }

        // 6) Log request for dashboard
        self::log_request([
            'ts'           => time(),
            'ip'           => $ip,
            'country'      => $country,
            'method'       => $method,
            'uri'          => $uri,
            'ua'           => $ua,
            'risk'         => $risk,
            'threat'       => $threat,
            'confidence'   => $confidence,
            'decision'     => $decision,
            'whitelisted'  => 0,
            'blacklisted'  => 0,
            'cache'        => $cache_hit,
            'fw_enabled'   => 1,
            'api_response' => $api_data,
        ]);


            // Threat map log
            self::maybe_log_threat_event($ip, $api_data, $decision);
            
        // 7) Apply action
        if ($decision === 'block') {
            $score_for_ui = $threat !== null ? $threat : 0;
            self::render_block_page($ip, $score_for_ui, is_array($api_data) ? $api_data : []);
            exit;
        }

if ($decision === 'challenge') {
// NEVER cache the redirect response itself (this is the loop killer)
if (!defined('DONOTCACHEPAGE')) {
    define('DONOTCACHEPAGE', true); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
}

nocache_headers();
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// LiteSpeed explicit
header('X-LiteSpeed-NoCache: on');
header('X-LiteSpeed-Cache-Control: no-cache');
header('X-LiteSpeed-Cache-Control: no-store');

// debug - 
header('X-IPIntel-Decision: challenge');

    // FINAL GUARD: do not re-challenge verified IPs
    if (self::has_valid_human_cookie()) {
        return;
    }



    $target = rawurlencode($uri ?: '/');

    wp_safe_redirect(
        add_query_arg(
            ['ipintel_challenge' => '1', 'target' => $target],
            home_url('/')
        ),
        302
    );
    exit;
}



        // decision = allow → continue to WordPress
    }

    /**
     * API lookup against IPIntel endpoint
     */
    public static function lookup($ip)
    {
        $api_key = get_option('ipintel_api_key', '');
        if (!$api_key) {
            return ['error' => 'Missing API key'];
        }

        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['error' => 'Invalid IP address'];
        }

        $url = add_query_arg([
            'ip'      => $ip,
            'api_key' => $api_key,
        ], IPINTEL_API_ENDPOINT);

        $response = wp_remote_get($url, [
            'timeout' => 2,
            'headers' => ['Accept' => 'application/json'],
        ]);

        if (is_wp_error($response)) {
           // error_log("url: " . $url . " | response: " . $response->get_error_message());
            return ['error' => $response->get_error_message()];
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($code !== 200) {
            return ['error' => 'API HTTP ' . $code . ' response'];
        }

        $data = json_decode($body, true);
        if (!is_array($data)) {
           // error_log("Invalid JSON response");
            return ['error' => 'Invalid JSON response'];
        }

        // Cache usage for dashboard
        if (isset($data['api_usage'])) {
            self::set_cached_api_usage([
                'plan'        => $data['api_plan']    ?? '',
                'usage'       => $data['api_usage']   ?? [],
                'response_ms' => $data['response_ms'] ?? 0,
            ]);
        }

        return $data;
    }




    /**
     * Client IP extraction
     */
    public static function get_client_ip()
    {
        $keys = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ($keys as $key) {
            if (!empty($_SERVER[$key])) {
            
             $value = sanitize_text_field(wp_unslash($_SERVER[$key]));


                if ($key === 'HTTP_X_FORWARDED_FOR') {
                    $parts = explode(',', $value);
                    $value = trim($parts[0]);
                }

                $value = trim($value);
                if (filter_var($value, FILTER_VALIDATE_IP)) {
                    return $value;
                }
            }
        }

        return null;
    }

    /**
     * API usage cache (for settings dashboard)
     */
    public static function get_cached_api_usage()
    {
        $cached = get_option('ipintel_last_usage', null);
        $last   = (int) get_option('ipintel_last_usage_time', 0);

        // 5-minute TTL
        if ($cached && (time() - $last) < 300) {
            return $cached;
        }

        return null;
    }

    public static function set_cached_api_usage($data)
    {
        if (!is_array($data) || empty($data)) {
            return;
        }

        update_option('ipintel_last_usage', $data);
        update_option('ipintel_last_usage_time', time());
    }

    /**
     * Whitelist helpers
     */
    protected static function get_whitelist_ips()
    {
        $raw = get_option('ipintel_whitelist', '');
        if (!$raw) return [];

        $lines = preg_split('/\r\n|\r|\n/', $raw);
        $out   = [];

        foreach ($lines as $line) {
            $ip = trim($line);
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
                $out[] = $ip;
            }
        }

        return $out;
    }

    protected static function is_whitelisted_ip($ip)
    {
        static $cache = null;
        if ($cache === null) {
            $cache = self::get_whitelist_ips();
        }
        return in_array($ip, $cache, true);
    }

    /**
     * Blacklist helpers
     */
    protected static function get_blacklist_ips()
    {
        $raw = get_option('ipintel_blacklist', '');
        if (!$raw) return [];

        $lines = preg_split('/\r\n|\r|\n/', $raw);
        $out   = [];

        foreach ($lines as $line) {
            $ip = trim($line);
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
                $out[] = $ip;
            }
        }

        return $out;
    }

    protected static function is_blacklisted_ip($ip)
    {
        static $cache = null;
        if ($cache === null) {
            $cache = self::get_blacklist_ips();
        }
        return in_array($ip, $cache, true);
    }

    /**
     * Risk formula 0–250
     */
    protected static function compute_risk($threat, $confidence)
    {
        $th = max(0, min(100, (int) $threat));
        $cf = max(0, min(100, (int) $confidence));

        $risk = pow($th, 1.2) * ($cf / 100);
        $risk = min(250, round($risk, 2));

        return $risk;
    }

    protected static function extract_threat_and_confidence(array $data)
    {
        $th = 0;
        if (isset($data['threat_score'])) {
            $th = (int) $data['threat_score'];
        } elseif (isset($data['score'])) {
            $th = (int) $data['score'];
        }

        $cf = 0;
        if (isset($data['confidence'])) {
            $cf = (int) $data['confidence'];
        } elseif (isset($data['confidence_level'])) {
            $cf = (int) $data['confidence_level'];
        }

        $th = max(0, min(100, $th));
        $cf = max(0, min(100, $cf));

        return [$th, $cf];
    }

    /**
     * IP cache helpers (per IP, plus index)
     */
    protected static function get_ip_cache_key($ip)
    {
        $safe = str_replace(['.', ':'], '_', $ip);
        return 'ipintel_cache_' . $safe;
    }


protected static function get_plan_ttl_seconds(): int
{
    // Default plan (safest fallback)
    $plan = 'ghost';

    // if stored in options
    $stored = get_option('ipintel_plan');
    if (is_string($stored) && $stored !== '') {
        $plan = strtolower($stored);
    }

    switch ($plan) {
        case 'overseer':
            return 3 * HOUR_IN_SECONDS;

        case 'oracle':
            return 6 * HOUR_IN_SECONDS;

        case 'sentinel':
            return 12 * HOUR_IN_SECONDS;

        case 'ghost':
        default:
            return 24 * HOUR_IN_SECONDS;
    }
}



    protected static function get_ip_cache($ip)
    {
        $key   = self::get_ip_cache_key($ip);
        $entry = get_option($key, null);

        if (!is_array($entry)) {
            return null;
        }

        $ttl = self::get_plan_ttl_seconds();


        $age = time() - (int) $entry['ts'];

        if ($age > $ttl) {
            delete_option($key);
            self::remove_from_cache_index($key);
            return null;
        }

        return $entry;
    }

    protected static function save_ip_cache($ip, array $entry)
    {
        $key         = self::get_ip_cache_key($ip);
        $entry['ts'] = time();

        update_option($key, $entry, false);
        self::add_to_cache_index($key);
    }

    protected static function add_to_cache_index($key)
    {
        $index = get_option('ipintel_cache_index', []);
        if (!is_array($index)) {
            $index = [];
        }

        if (!in_array($key, $index, true)) {
            $index[] = $key;
        }

        if (count($index) > 200000) {
            $index = array_slice($index, -200000);
        }

        update_option('ipintel_cache_index', $index, false);
    }

    protected static function remove_from_cache_index($key)
    {
        $index = get_option('ipintel_cache_index', []);
        if (!is_array($index) || empty($index)) {
            return;
        }

        $new = [];
        foreach ($index as $k) {
            if ($k !== $key) {
                $new[] = $k;
            }
        }

        if (count($new) !== count($index)) {
            update_option('ipintel_cache_index', $new, false);
        }
    }

    /**
     * Cron: prune old cache entries (>24h)
     */
    public static function cron_prune_cache()
    {
        $index = get_option('ipintel_cache_index', []);
        if (!is_array($index) || empty($index)) {
            return;
        }

        $now  = time();
        $keep = [];

        foreach ($index as $key) {
            $entry = get_option($key, null);
            if (!is_array($entry) || empty($entry['ts']) || ($now - (int) $entry['ts'] > DAY_IN_SECONDS)) {
                delete_option($key);
                continue;
            }
            $keep[] = $key;
        }

        update_option('ipintel_cache_index', $keep, false);
    }

    /**
     * Request log for dashboard table
     */
    protected static function log_request(array $row)
    {
        if (!isset($row['whitelisted'])) {
            $row['whitelisted'] = 0;
        }
        if (!isset($row['blacklisted'])) {
            $row['blacklisted'] = 0;
        }

        $log = get_option('ipintel_request_log', []);
        if (!is_array($log)) {
            $log = [];
        }

        $log[] = $row;

        $now   = time();
        $clean = [];

        foreach ($log as $entry) {
            if (!empty($entry['ts']) && ($now - (int)$entry['ts'] <= DAY_IN_SECONDS)) {
                $clean[] = $entry;
            }
        }

        // Limit requests in log
        if (count($clean) > 1000) {
            $clean = array_slice($clean, -1000);
        }

        update_option('ipintel_request_log', $clean, false);
    }

    /**
     * Threat log for map
     */
    protected static function maybe_log_threat_event($ip, array $data, string $decision)
    {
        if (empty($data['latitude']) || empty($data['longitude'])) {
            return;
        }

        $badge_flags = [];
        if (!empty($data['badges']) && is_array($data['badges'])) {
            foreach ($data['badges'] as $b) {
                if (!empty($b['flag'])) {
                    $badge_flags[] = $b['flag'];
                }
            }
        }

        $score = isset($data['threat_score']) ? (int) $data['threat_score'] : 0;

        $entry = [
            'ip'     => $ip,
            'lat'    => (float) $data['latitude'],
            'lon'    => (float) $data['longitude'],
            'score'  => $score,
            'badges' => $badge_flags,
            'decision'         => $decision,   
            'ts'     => time(),
        ];

        $log = get_option('ipintel_threat_log', []);
        if (!is_array($log)) {
            $log = [];
        }

        $log[] = $entry;

        $now   = time();
        $clean = [];
        foreach ($log as $row) {
            if (!empty($row['ts']) && ($now - (int) $row['ts'] <= DAY_IN_SECONDS)) {
                $clean[] = $row;
            }
        }
        if (count($clean) > 300) {
            $clean = array_slice($clean, -300);
        }

        update_option('ipintel_threat_log', $clean, false);
    }

    /**
     * Threat map AJAX
     */
    public static function ajax_threatmap()
    {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'Access denied']);
        }

        $log = get_option('ipintel_threat_log', []);
        if (!is_array($log)) $log = [];

        $now = time();
        $out = [];

        foreach ($log as $row) {
            if (!empty($row['ts']) && ($now - (int) $row['ts'] <= DAY_IN_SECONDS)) {
                $out[] = $row;
            }
        }

        wp_send_json($out);
    }

    /**
     * Challenge page
     */
    public static function maybe_render_challenge_page()
    {
    
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
if (!isset($_GET['ipintel_challenge'])) {
    return;
}

        $theme   = get_option('ipintel_challenge_theme', 'dark');
        $cssFile = $theme === 'light' ? 'challenge-light.css' : 'challenge-dark.css';

// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$target_raw = filter_input(INPUT_GET, 'target', FILTER_SANITIZE_URL);

$target = esc_url_raw($target_raw ?: '/');



        status_header(200);
    
if (!defined('DONOTCACHEPAGE')) {
    define('DONOTCACHEPAGE', true); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
}

if (!defined('DONOTCACHEOBJECT')) {
    define('DONOTCACHEOBJECT', true); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
}

if (!defined('DONOTCACHEDB')) {
    define('DONOTCACHEDB', true); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
}


nocache_headers();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


header('X-IPIntel-Page: challenge');

        ?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Verification Required</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet ?>
    <link rel="stylesheet" href="<?php echo esc_url( IPINTEL_URL . 'assets/' . $cssFile ); ?>">
</head>
<body>

<div class="ipintel-page">
    <div class="ipintel-card">

        <?php
        $site_logo_url = '';
        if (function_exists('get_custom_logo')) {
            $logo_id = get_theme_mod('custom_logo');
            if ($logo_id) {
                $logo_data = wp_get_attachment_image_src($logo_id, 'medium');
                if (!empty($logo_data[0])) {
                    $site_logo_url = $logo_data[0];
                }
            }
        }
        $site_name = get_bloginfo('name');
        ?>

        <div class="ipintel-brand">
            <?php if ($site_logo_url): ?>
                <div class="brand-logo">
                    <img src="<?php echo esc_url($site_logo_url); ?>" alt="">
                </div>
            <?php else: ?>
                <div class="brand-logo brand-logo-fallback">
                    <span><?php echo esc_html(mb_substr($site_name, 0, 1)); ?></span>
                </div>
            <?php endif; ?>

            <div class="brand-meta">
                <div class="brand-title"><?php echo esc_html($site_name); ?></div>
                <div class="brand-subtitle">Verification Required</div>
            </div>
        </div>

        <h1 class="block-title">Verify you are human</h1>

        <p class="block-text">
            Before continuing, please complete a quick verification.
        </p>

        <label class="checkwrap big-check">
            <input type="checkbox" id="ipintel-check">
            <span class="checkmark"></span>
            <span class="labeltext">I'm not a bot</span>
        </label>

        <button id="ipintel-continue" class="ipintel-btn big-btn">Continue</button>

        <div id="ipintel-error" class="block-text secondary" style="margin-top:12px;"></div>

        <div class="ipintel-footer">
            <div class="ipintel-mini">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="20" height="20" aria-hidden="true" focusable="false">
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
        
     <polygon points="41,11 81,11 111,41 111,81 81,111 41,111 11,81 11,41" stroke="#000000" stroke-width="1" fill="none"></polygon>

<!--neon -->
<polygon points="40,10 80,10 110,40 110,80 80,110 40,110 10,80 10,40" stroke="#00FFFF" stroke-width="2" fill="none"></polygon>

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
      </svg>
            </div>
            <div class="ipintel-footer-text">
                Protected by
                <a href="https://ipintel.ai" target="_blank" rel="nofollow noopener">
                    IPIntel.ai
                </a>
            </div>
        </div>

    </div>
</div>

<script>
let IPINTEL_TARGET = "<?php echo esc_js($target); ?>";
let IPINTEL_AJAX   = "<?php echo esc_js(admin_url('admin-ajax.php')); ?>";
</script>
<?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript ?>
<script src="<?php echo esc_url( IPINTEL_URL); ?>assets/ipintel-challenge.js"></script>

</body>
</html>
        <?php
        exit;
    }

    /**
     * Human verification cookie
     */
    public static function has_valid_human_cookie()
    {
        if (empty($_COOKIE['ipintel_human_ok'])) return false;

    $raw = isset($_COOKIE['ipintel_human_ok'])
    ? sanitize_text_field(wp_unslash($_COOKIE['ipintel_human_ok']))
    : '';

        $parts = explode('|', $raw);
        if (count($parts) !== 3) return false;

        list($ip, $ts, $sig) = $parts;

        if ($ip !== self::get_client_ip()) return false;

        $ttl = (int) get_option('ipintel_challenge_duration', 10800);
        if (time() - (int)$ts > $ttl) return false;

        $expected = hash_hmac('sha256', $ip . '|' . $ts, AUTH_SALT);
        return hash_equals($expected, $sig);
    }

    /**
     * AJAX: validate challenge data and set cookie
     */
     // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    public static function ajax_challenge_verify()
    {
        $body = json_decode(file_get_contents('php://input'), true);
        if (!$body) wp_send_json_error(['msg' => 'No data']);

        $ip    = self::get_client_ip();
        $start = intval($body['start'] ?? 0);
        $click = intval($body['click'] ?? 0);
        $moves = intval($body['moves'] ?? 0);

        if ($click - $start < 350) wp_send_json_error(['msg' => 'Too fast']);
        if ($moves < 2)           wp_send_json_error(['msg' => 'No movement detected']);

        $ts  = time();
        $sig = hash_hmac('sha256', $ip . '|' . $ts, AUTH_SALT);

        $ttl = (int) get_option('ipintel_challenge_duration', 10800);
// HARD allow for this IP (short TTL)
set_transient(
    'ipintel_allow_' . md5($ip),
    1,
    300 // 5 min
);

        setcookie(
            'ipintel_human_ok',
            $ip . '|' . $ts . '|' . $sig,
            time() + $ttl,
            COOKIEPATH,
            COOKIE_DOMAIN,
            is_ssl(),
            true
        );

        // Mark last log entry as challenge_passed
        $log = get_option('ipintel_request_log', []);
        if (is_array($log) && !empty($log)) {
            for ($i = count($log) - 1; $i >= 0; $i--) {
                if (!empty($log[$i]['ip']) && $log[$i]['ip'] === $ip) {
                    $log[$i]['challenge_passed'] = true;
                    break;
                }
            }
            update_option('ipintel_request_log', $log);
        }
        
        
        
        $threat_log = get_option('ipintel_threat_log', []);
if (is_array($threat_log)) {
    for ($i = count($threat_log) - 1; $i >= 0; $i--) {
        if (!empty($threat_log[$i]['ip']) && $threat_log[$i]['ip'] === $ip) {
            $threat_log[$i]['challenge_passed'] = true;
            $threat_log[$i]['decision'] = 'allow';
            break;
        }
    }
    update_option('ipintel_threat_log', $threat_log, false);
}




$target = $body['target'] ?? '/';

$bridge = add_query_arg(
    'ipintel_verified',
    '1',
    $target
);

wp_send_json_success([
    'redirect' => $bridge
]);


    }

    /**
     * Block page
     */
    protected static function render_block_page($ip, $score, $data)
    {
        status_header(403);
        
                
if (!defined('DONOTCACHEPAGE')) {
    define('DONOTCACHEPAGE', true); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
}

if (!defined('DONOTCACHEOBJECT')) {
    define('DONOTCACHEOBJECT', true); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
}

if (!defined('DONOTCACHEDB')) {
    define('DONOTCACHEDB', true); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
}


nocache_headers();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


header('X-IPIntel-Page: block');

        nocache_headers();

        $theme   = get_option('ipintel_block_theme', 'dark');
        $cssFile = $theme === 'light' ? 'block-light.css' : 'block-dark.css';

        $site_logo_url = '';
        if (function_exists('get_custom_logo')) {
            $logo_id = get_theme_mod('custom_logo');
            if ($logo_id) {
                $logo_data = wp_get_attachment_image_src($logo_id, 'medium');
                if (!empty($logo_data[0])) {
                    $site_logo_url = $logo_data[0];
                }
            }
        }

        $site_name = get_bloginfo('name');



header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


        ?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="robots" content="noindex,nofollow">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Access temporarily restricted</title>
	<?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet ?>
    <link rel="stylesheet" href="<?php echo esc_url(IPINTEL_URL . 'assets/' . $cssFile); ?>">
</head>
<body>

<div class="ipintel-page">
    <div class="ipintel-card">

        <div class="ipintel-brand">
            <?php if ($site_logo_url): ?>
                <div class="brand-logo">
                    <img src="<?php echo esc_url($site_logo_url); ?>" alt="<?php echo esc_attr($site_name); ?>">
                </div>
            <?php else: ?>
                <div class="brand-logo brand-logo-fallback">
                    <span><?php echo esc_html(mb_substr($site_name, 0, 1)); ?></span>
                </div>
            <?php endif; ?>

            <div class="brand-meta">
                <div class="brand-title"><?php echo esc_html($site_name); ?></div>
                <div class="brand-subtitle">Request blocked by security policy</div>
            </div>
        </div>

        <h1 class="block-title">Access temporarily restricted</h1>

        <p class="block-text">
            For security reasons, this request cannot continue.
        </p>

        <div class="ip-strip">
            <span class="ip-label">IP address</span>
            <span class="ip-value"><?php echo esc_html($ip); ?></span>
        </div>

        <p class="block-text secondary">
            If you believe this is an error, try again later or contact the site owner.
        </p>

        <div class="ipintel-footer">
            <div class="ipintel-mini">
               <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="20" height="20" aria-hidden="true" focusable="false">
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
        
     <polygon points="41,11 81,11 111,41 111,81 81,111 41,111 11,81 11,41" stroke="#000000" stroke-width="1" fill="none"></polygon>

<!--neon -->
<polygon points="40,10 80,10 110,40 110,80 80,110 40,110 10,80 10,40" stroke="#00FFFF" stroke-width="2" fill="none"></polygon>

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
      </svg>
            </div>
            <div class="ipintel-footer-text">
                Protected by
                <a href="https://ipintel.ai" target="_blank" rel="nofollow noopener">
                    IPIntel.ai
                </a>
            </div>
        </div>

    </div>
</div>

</body>
</html>
        <?php
        exit;
    }

    /**
     * Threat stats for dashboard HUD
     */
    public static function ajax_threat_stats()
    {
        $log = get_option('ipintel_request_log', []);
        if (!is_array($log)) $log = [];

        $challenged         = 0;
        $blocked            = 0;
        $passed             = 0;
        $whitelisted_count  = 0;
        $blacklisted_count  = 0;
        $badges             = [];

        foreach ($log as $entry) {
            $dec = isset($entry['decision']) ? strtolower($entry['decision']) : '';

            if (!empty($entry['challenge_passed'])) {
                $passed++;
            }
            if ($dec === 'challenge') {
                $challenged++;
            }
            if ($dec === 'block') {
                $blocked++;
            }
            if (!empty($entry['whitelisted'])) {
                $whitelisted_count++;
            }
            if (!empty($entry['blacklisted'])) {
                $blacklisted_count++;
            }

            if (!empty($entry['api_response']['badges']) && is_array($entry['api_response']['badges'])) {
                foreach ($entry['api_response']['badges'] as $b) {
                    $key = ($b['emoji'] ?? '') . ' ' . ($b['label'] ?? '');
                    $key = trim($key);
                    if ($key === '') continue;
                    if (!isset($badges[$key])) $badges[$key] = 0;
                    $badges[$key]++;
                }
            }
        }

        wp_send_json([
            'challenged'  => $challenged,
            'blocked'     => $blocked,
            'passed'      => $passed,
            'whitelisted' => $whitelisted_count,
            'blacklisted' => $blacklisted_count,
            'badges'      => $badges,
        ]);
    }
    
    
public static function ajax_map_points() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['error' => 'Access denied']);
    }

    $log = get_option('ipintel_threat_log', []);
    if (!is_array($log)) $log = [];

    $now = time();
    $out = [];

    foreach ($log as $row) {
        if (empty($row['lat']) || empty($row['lon'])) continue;
        if (!empty($row['ts']) && ($now - (int)$row['ts'] > DAY_IN_SECONDS)) continue;
//error_log(print_r($row, true));

$out[] = [
    'ip'               => $row['ip'] ?? '',
    'lat'              => (float)$row['lat'],
    'lon'              => (float)$row['lon'],
    'score'            => (int)($row['score'] ?? 0),
    'decision'         => $row['decision'] ?? 'allow',
    'challenge_passed' => !empty($row['challenge_passed']),
    'blacklisted'      => !empty($row['blacklisted']),
];

    }

    wp_send_json($out);
}


}


/////


if (!function_exists('ipintel_render_badge')) {

function ipintel_render_badge() {

    // dont show in admin
    if (is_admin()) {
        return;
    }

    // not for login admin
    if (is_user_logged_in() && current_user_can('manage_options')) {
        return;
    }

    // option: off | dark | light
    $mode = get_option('ipintel_badge_mode', 'off');

    if ($mode === 'off') {
        return;
    }

    $theme = $mode === 'light' ? 'light' : 'dark';

    $utm = [
        'utm_source'   => wp_parse_url(home_url(), PHP_URL_HOST),
        'utm_medium'   => 'footer_badge',
        'utm_campaign' => 'wp_plugin'
    ];

    $url = 'https://ipintel.ai/?' . http_build_query($utm);
    ?>

    <div class="ipintel-footer-badge ipintel-badge-<?php echo esc_attr($theme); ?>">
        <a href="<?php echo esc_url($url); ?>" target="_blank" rel="noopener">
            <span class="ipintel-badge-logo">
                <!-- SVG или IMG тук -->
            </span>
            <span class="ipintel-badge-text">Protected by IPIntel.ai</span>
        </a>
    </div>

    <?php
}
}


