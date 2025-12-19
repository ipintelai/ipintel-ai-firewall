<?php
if (!defined('ABSPATH')) exit;

function ipintel_render_dashboard() {


    if (!current_user_can('manage_options')) {
        wp_die('Access denied.');
    }


// Handle kill switch toggle
if (
    isset($_POST['ipintel_toggle_kill']) &&
    check_admin_referer('ipintel_kill_switch')
) {
    $raw_state = sanitize_text_field(
        wp_unslash( $_POST['kill_new_state'] ?? 'off' )
    );

    $new_state = ($raw_state === 'on') ? 'on' : 'off';

    update_option('ipintel_kill_switch', $new_state);

    // Reload page to update UI instantly
    echo '<script>location.reload();</script>';
    exit;
}



    $api_key   = get_option('ipintel_api_key', '');
    $mode      = get_option('ipintel_mode', 'monitor');
    $threshold = (int)get_option('ipintel_block_threshold', 70);

    // Get cached API usage from class-core.php
    $usage_data = IPIntel_Core::get_cached_api_usage();
    
    // fallback to last usage if current is incomplete
$last_full_usage = get_option('ipintel_last_usage', null);

$has_current = (
    $usage_data &&
    isset($usage_data['usage']) &&
    is_array($usage_data['usage']) &&
    !empty($usage_data['usage'])
);

// if current data is missing → fallback to last valid
if (!$has_current && $last_full_usage) {
    $usage_data = $last_full_usage;
    $has_current = true;
}



    // Helper to parse "X/Y" format
    function ipintel_parse_limit($str) {
        if (!$str || strpos($str, '/') === false) {
            return [0, 0, 0];
        }
        list($used, $limit) = explode('/', $str);
        $used  = (int)$used;
        $limit = (int)$limit;
        $left  = max(0, $limit - $used);
        return [$used, $limit, $left];
    }

    // Parse usage if exists
    if ($usage_data && isset($usage_data['usage'])) {
        list($sec_used, $sec_limit, $sec_left) = ipintel_parse_limit($usage_data['usage']['sec_limit'] ?? '');
        list($min_used, $min_limit, $min_left) = ipintel_parse_limit($usage_data['usage']['min_limit'] ?? '');
        list($day_used, $day_limit, $day_left) = ipintel_parse_limit($usage_data['usage']['day_limit'] ?? '');
    }
?>
<div class="wrap ipintel-wrap">

    <!-- HEADER -->
<?php
$plugin_data = get_file_data(
    IPINTEL_PATH . 'ipintel-ai-firewall.php',
    ['Version' => 'Version']
);
$version = $plugin_data['Version'];
?>

<div class="ipintel-header">
     <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="42" height="42" aria-hidden="true" focusable="false">
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
    <h1 style="display:flex; align-items:center; gap:10px;">
        IPIntel AI Firewall
        <span class="version">
            v<?php echo esc_html($version); ?>
        </span>
    </h1>
</div>



<?php if (!$api_key): ?>

    <div class="ipintel-card-full">
        <h2>Connect IPIntel.ai to enable protection</h2>
        <p>This site is using the IPIntel AI Firewall plugin, but no API key has been configured yet.</p>

        <div class="ipintel-actions">
            <a href="https://ipintel.ai/register" target="_blank" class="ipintel-btn">Get Free API Key</a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=ipintel-settings')); ?>" class="ipintel-btn-secondary">
                Go to Settings
            </a>
        </div>
    </div>

<?php else: ?>

    <!-- MAIN GRID ROW -->
    <div class="ipintel-grid">

        <!-- FIREWALL STATUS -->
<?php
// Load kill switch value
$kill_switch = get_option('ipintel_kill_switch', 'on'); // default ON

// Whitelist count
$whitelist_raw = get_option('ipintel_whitelist', '');
$whitelist_count = 0;
if ($whitelist_raw) {
    $whitelist_count = count(array_filter(array_map('trim', explode("\n", $whitelist_raw))));
}

//blacklist count
$blacklist_raw = get_option('ipintel_blacklist', '');
$blacklist_count = 0;
if ($blacklist_raw) {
    $blacklist_count = count(array_filter(array_map('trim', explode("\n", $blacklist_raw))));
}


?>

<div class="ipintel-card ipintel-killcard">
    <h3>Firewall Master Switch</h3>

    <div class="ipintel-kill-container">
        
        <!-- CYBERPUNK INDICATOR -->
        <div class="ipintel-status-led <?php echo $kill_switch === 'on' ? 'led-on' : 'led-off'; ?>"></div>

        <!-- LABEL -->
        <span class="ipintel-status-label">
            <?php echo $kill_switch === 'on' ? 'Firewall ACTIVE' : 'Firewall DISABLED'; ?>
        </span>

        <!-- TOGGLE FORM -->
        <form method="post" class="ipintel-kill-form">
            <?php wp_nonce_field('ipintel_kill_switch'); ?>
            <input type="hidden" name="ipintel_toggle_kill" value="1">
            <input type="hidden" name="kill_new_state" value="<?php echo $kill_switch === 'on' ? 'off' : 'on'; ?>">

            <button type="submit" class="ipintel-kill-btn">
                <?php echo $kill_switch === 'on' ? 'Turn OFF' : 'Turn ON'; ?>
            </button>
        </form>
    </div>

 
    
    <?php
$req_log = get_option('ipintel_request_log', []);
$req_count_24h = is_array($req_log) ? count($req_log) : 0;
?>
<div class="ipintel-requests-line">
    Total requests: 
    <strong><?php echo esc_html($req_count_24h); ?></strong> 
</div>

   <div class="ipintel-whitelist-line">
        Whitelist IPs: 
        <a href="<?php echo esc_url(admin_url('admin.php?page=ipintel-settings')); ?>">
            <?php echo esc_html($whitelist_count); ?>
        </a>
       
    </div>
    <div class="ipintel-blacklist-line">
    Blacklist IPs:
    <a href="<?php echo esc_url(admin_url('admin.php?page=ipintel-settings')); ?>">
        <?php echo esc_html($blacklist_count); ?>
    </a>
</div>

</div>


        <!-- THREAT OVERVIEW -->
        <div class="ipintel-card">
            <h3>Threat Overview</h3>
          <div id="threat-overview">
   <div class="ov-line">
    Challenged: <span id="ov-challenged" class="ov-num ov-chal">0</span>
</div>
<div class="ov-line">
    Blocked: <span id="ov-blocked" class="ov-num ov-blk">0</span>
</div>
<div class="ov-line">
    Passed: <span id="ov-passed" class="ov-num ov-pass">0</span>
</div>
<div class="ov-line">Whitelisted: <span id="ov-whitelisted" class="ov-num ov-wl">0</span></div>
<div class="ov-line">Blacklisted: <span id="ov-blacklisted" class="ov-num ov-bl">0</span></div>

<hr class="ov-divider">


    

    <div id="badge-list" class="ov-badges"></div>
</div>

        </div>

        <!-- API USAGE CARD -->
        <div class="ipintel-card ipintel-usage-card">
            <h3>API Usage</h3>

<?php if (!$has_current): ?>
    <p>Waiting for first API request…</p>
<?php else: ?>


<?php 
    $plan = esc_html($usage_data['plan']);

    // Percentages
    $day_percent = $day_limit > 0 ? round(($day_used / $day_limit) * 100) : 0;
    $min_percent = $min_limit > 0 ? round(($min_used / $min_limit) * 100) : 0;

    // Colors
    function ipintel_color($pct) {
        if ($pct < 60) return '#00e5ff';
        if ($pct < 85) return '#ffb64d';
        return '#ff4d4d';
    }

    $day_color = ipintel_color($day_percent);
    $min_color = ipintel_color($min_percent);

    function ipintel_glow($pct) {
        if ($pct < 60) return '0 0 12px';
        if ($pct < 85) return '0 0 20px';
        return '0 0 26px';
    }

    $day_glow = ipintel_glow($day_percent);
    $min_glow = ipintel_glow($min_percent);

    $day_high = $day_percent >= 85 ? '1' : '0';
    $min_high = $min_percent >= 85 ? '1' : '0';
?>

            <!-- PLAN TITLE -->
            <div class="ipintel-plan">
                Subscription plan: 
                <span class="ipintel-plan-label"><?php echo esc_html($plan); ?></span>

<?php if (strtolower($plan) !== 'overseer'): ?>
                <a href="https://ipintel.ai/dashboard?open_plan_modal=1" target="_blank" class="ipintel-upgrade-btn">Upgrade</a>
<?php endif; ?>
            </div>

            <!-- CIRCLES -->
            <div class="ipintel-usage-circles">

                <div class="ipintel-circle-big"
                     data-high="<?php echo esc_attr($day_high); ?>"
                     style="--pct:<?php echo esc_attr($day_percent); ?>;
                            --clr:<?php echo esc_attr($day_color); ?>;
                            --glow:<?php echo esc_attr($day_glow); ?>;">
                    <div class="ipintel-circle-inner">
                        <div class="ipintel-circle-value"><?php echo esc_attr($day_used)." / ".esc_attr($day_limit); ?></div>
                        <div class="ipintel-circle-label">Day</div>
                    </div>
                </div>

                <div class="ipintel-circle-small"
                     style="--pct:<?php echo esc_attr($min_percent); ?>;
                            --clr:<?php echo esc_attr($min_color); ?>;
                            --glow:<?php echo esc_attr($min_glow); ?>;">
                    <div class="ipintel-circle-inner-small">
                        <div class="ipintel-circle-value-small"><?php echo esc_attr($min_used)." / ".esc_attr($min_limit); ?></div>
                        <div class="ipintel-circle-label-small">Min</div>
                    </div>
                </div>

            </div>

            <!-- LATENCY -->
            <p class="ipintel-latency">
                Latency: <strong><?php echo esc_html($usage_data['response_ms']); ?> ms</strong>
            </p>

<?php endif; ?>
        </div> <!-- END API USAGE CARD -->

    </div> <!-- END GRID -->

<?php endif; ?>

<!-- GLOBAL MAP + VIDEO ROW -->
<div class="ipintel-wide-grid">

<!-- MAP + REQUEST LOG TABS -->
<div class="ipintel-card ipintel-map-card">

    <!-- TAB HEADERS -->
    <div class="ipintel-tabs">
        <button class="ipintel-tab-btn active" data-tab="tab-map">Map</button>
        <button class="ipintel-tab-btn" data-tab="tab-requests">Request</button>
    </div>

    <div class="ipintel-tab-content">

        <!-- TAB 1: MAP -->
        <div id="tab-map" class="ipintel-tab-pane active">
            <div id="ipintel-map" style="height:380px;"></div>
        </div>

<!-- TAB 2: REQUEST LOG TABLE -->
<div id="tab-requests" class="ipintel-tab-pane">

    <?php 
    $req_log = get_option('ipintel_request_log', []);
    if (!is_array($req_log)) $req_log = [];

    // last records first
    $req_log = array_reverse($req_log);

    ?>

<div class="ipintel-log-wrap">
    <table class="ipintel-log-table">
        <thead>
        <tr>
            <th>Time</th>
            <th>IP</th>
            <th>Ctry</th>
            <th>M</th>
            <th>URI</th>
            <th>UA</th>
            <th style="text-align:left">Risk</th>
            <th style="text-align:left">Thr</th>
            <th style="text-align:left">Conf</th>
            <th>Decision</th>
            <th>Cache</th>
        </tr>
        </thead>
        <tbody>

        <?php if (empty($req_log)): ?>
            <tr><td colspan="11" class="empty">No requests logged in the last 24 hours.</td></tr>
        <?php else: foreach ($req_log as $row): ?>

            <tr>
                <td><?php echo esc_html(gmdate('H:i:s', $row['ts'])); ?></td>

                <td class="ipcell ellipsis" title="<?php echo esc_attr($row['ip']); ?>">
                   <a href="https://ipintel.ai/ip/<?php echo esc_attr($row['ip']); ?>"
                       target="_blank" class="ip-ext">
                        <span class="dashicons dashicons-search"></span>
                    </a>
                    <?php echo esc_html($row['ip']); ?>
                 
                </td>

                <td><center><?php echo esc_html($row['country'] ?? ''); ?></center></td>

                <td><center><?php echo esc_html($row['method']); ?></center></td>

                <td class="ellipsis" title="<?php echo esc_attr($row['uri']); ?>">
                    <?php echo esc_html($row['uri']); ?>
                </td>

                <td class="ellipsis" title="<?php echo esc_attr($row['ua']); ?>">
                    <?php echo esc_html($row['ua']); ?>
                </td>

                <td><?php echo esc_attr($row['risk']); ?></td>
                <td><?php echo intval($row['threat']); ?></td>
                <td><?php echo intval($row['confidence']); ?></td>

<td>
    <?php if (!empty($row['whitelisted'])): ?>

        <span class="badge badge-whitelisted">WHITELIST</span>

    <?php elseif (!empty($row['blacklisted'])): ?>

        <span class="badge badge-blacklisted">BLACKLIST</span>

    <?php elseif ($row['decision'] === 'block'): ?>

        <span class="badge badge-block">BLOCK</span>

    <?php elseif ($row['decision'] === 'challenge'): ?>

        <?php if (!empty($row['challenge_passed'])): ?>
            <span class="badge badge-challenge-pass">CHALLENGE ✓</span>
        <?php else: ?>
            <span class="badge badge-challenge">CHALLENGE</span>
        <?php endif; ?>

    <?php else: ?>

        <span class="badge badge-allow">ALLOW</span>

    <?php endif; ?>
</td>



                <td class="cachecell">
                    <?php if ($row['cache']): ?>
                        <span class="cache-hit" title="Cached result"></span>
                    <?php else: ?>
                        <span class="cache-miss" title="Live API"></span>
                    <?php endif; ?>
                </td>

            </tr>

        <?php endforeach; endif; ?>

        </tbody>
    </table>
</div>



</div>



    </div>
</div>


    <!-- VIDEO -->
    <div class="ipintel-card ipintel-video-card">
       <h3>Recent Global Threat Activity (last 24h)</h3>
        <div class="ipintel-video-wrapper">
<iframe
    src="https://www.youtube.com/embed?listType=playlist&list=PLKJQpd4ucuwgQpfoPZYl6CyKuaC7b7Ax3&rel=0&mute=0"
    allowfullscreen>
</iframe>




      
                
                
        </div>
        
        




    </div>

</div>



</div> <!-- END WRAP -->


<script>
document.querySelectorAll('.ipintel-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {

        document.querySelectorAll('.ipintel-tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.ipintel-tab-pane').forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');
    });
});
</script>

<script>
jQuery(function($){

    function loadThreatStats() {
        $.post(ajaxurl, { action: 'ipintel_threat_stats' }, function(res){

            $('#ov-challenged').text(res.challenged);
            $('#ov-blocked').text(res.blocked);
            $('#ov-passed').text(res.passed);
	    $('#ov-whitelisted').text(res.whitelisted);
	    $('#ov-blacklisted').text(res.blacklisted);
            // Render badges dynamically
            let html = '';
            $.each(res.badges, function(name, count) {
                html += `
                    <div class="badge-item" title="${name.split(' ').slice(1).join(' ')}">
                        <span class="badge-emoji" >${name.split(' ')[0]}</span>
                  
                        <span class="badge-count">${count}</span>
                    </div>
                `;
            });

            $('#badge-list').html(html);
        });
    }

    loadThreatStats();
    setInterval(loadThreatStats, 15000);
});
</script>

<?php
}

