<?php

if (!defined('ABSPATH')) exit;

function ipintel_render_settings_page() {

    if (!current_user_can('manage_options')) {
        wp_die('Access denied.');
    }

    $updated = false;

    // ---------------------------------------
    // SAVE SETTINGS
    // ---------------------------------------
    if (isset($_POST['ipintel_save_settings']) && check_admin_referer('ipintel_save_settings')) {

$api_key = isset($_POST['ipintel_api_key'])
    ? sanitize_text_field( wp_unslash( $_POST['ipintel_api_key'] ) )
    : '';


        // NEW SLIDER VALUES
$challenge = isset($_POST['ipintel_challenge_threshold'])
    ? absint( wp_unslash( $_POST['ipintel_challenge_threshold'] ) )
    : 60;


$block = isset($_POST['ipintel_block_threshold'])
    ? absint( wp_unslash( $_POST['ipintel_block_threshold'] ) )
    : 180;



        if ($challenge < 1) $challenge = 1;
        if ($challenge > 250) $challenge = 250;

        if ($block < 1) $block = 1;
        if ($block > 250) $block = 250;

        // WHITELIST
$wh_raw = isset($_POST['ipintel_whitelist'])
    ? sanitize_textarea_field( wp_unslash( $_POST['ipintel_whitelist'] ) )
    : '';


        $wh_clean = implode("\n", array_filter(array_map('trim', explode("\n", $wh_raw))));
        update_option('ipintel_whitelist', $wh_clean);
        
        // BLACKLIST
$bl_raw = isset($_POST['ipintel_blacklist'])
    ? sanitize_textarea_field( wp_unslash( $_POST['ipintel_blacklist'] ) )
    : '';


$bl_clean = implode("\n", array_filter(array_map('trim', explode("\n", $bl_raw))));
update_option('ipintel_blacklist', $bl_clean);


        update_option('ipintel_api_key', $api_key);
        update_option('ipintel_challenge_threshold', $challenge);
        update_option('ipintel_block_threshold', $block);

        $updated = true;
        
        if (isset($_POST['ipintel_challenge_theme'])) {
        $theme = $_POST['ipintel_challenge_theme'] === 'light' ? 'light' : 'dark';
        update_option('ipintel_challenge_theme', $theme);
    }
    
      if (isset($_POST['ipintel_block_theme'])) {
        $theme = $_POST['ipintel_block_theme'] === 'light' ? 'light' : 'dark';
        update_option('ipintel_block_theme', $theme);
    }

	if (isset($_POST['ipintel_challenge_duration'])) {
    	update_option('ipintel_challenge_duration', intval($_POST['ipintel_challenge_duration']));
	}

$badge_mode = isset($_POST['ipintel_footer_badge'])
    ? sanitize_text_field( wp_unslash( $_POST['ipintel_footer_badge'] ) )
    : 'off';

if (!in_array($badge_mode, ['off','dark','light'], true)) $badge_mode = 'off';
update_option('ipintel_footer_badge', $badge_mode);


    }






    // ---------------------------------------
    // LOAD OPTIONS
    // ---------------------------------------
    $api_key   = get_option('ipintel_api_key', '');
    $challenge = (int)get_option('ipintel_challenge_threshold', 60);
    $block     = (int)get_option('ipintel_block_threshold', 180);
    $whitelist = get_option('ipintel_whitelist', '');

    // TEST LOOKUP
    $lookup_result = null;
    if (!empty($_POST['ipintel_run_test']) && check_admin_referer('ipintel_test_lookup')) {
       $ip = isset($_POST['ipintel_test_ip'])
    ? sanitize_text_field( wp_unslash( $_POST['ipintel_test_ip'] ) )
    : '';

        if ($ip) $lookup_result = IPIntel_Core::lookup($ip);
    }
    
    

   
?>
<div class="wrap ipintel-wrap">

<?php if ($updated): ?>
<div class="ipintel-alert" id="ipintel-alert">
    <span class="msg">Settings saved successfully.</span>
    <button class="close-btn" 
        onclick="document.getElementById('ipintel-alert').style.opacity='0'; setTimeout(()=>document.getElementById('ipintel-alert').remove(), 300);">
        ×
    </button>
</div>
<?php endif; ?>
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
        <h1 style="display:flex; align-items:center; gap:10px;">IPIntel AI Firewall 
        <span class="version">
            v<?php echo esc_html($version); ?>
        </span> Settings</h1>
    </div>

    <div class="ipintel-card">
        <h3>API Configuration</h3>

        <form method="post">
            <?php wp_nonce_field('ipintel_save_settings'); ?>
            <input type="hidden" name="ipintel_save_settings" value="1">

            <table class="form-table" role="presentation">

                <!-- API KEY -->
                <tr>
                    <th><label for="ipintel_api_key">API Key</label></th>
                    <td>
                        <input type="text" name="ipintel_api_key" id="ipintel_api_key"
                               value="<?php echo esc_attr($api_key); ?>" class="regular-text">
                    </td>
                </tr>

                <!-- NEW CHALLENGE SLIDER -->
                <tr>
                    <th><label for="ipintel_challenge_threshold">Challenge Threshold</label>
                      <p class="description">IPs scoring above this value will be challenged.</p>
                    </th>
                    <td>
                        <input type="range" min="1" max="250" id="ipintel_challenge_threshold"
                               name="ipintel_challenge_threshold"
                               value="<?php echo (int)$challenge; ?>"
                               oninput="document.getElementById('challenge_val').innerText=this.value">

                        <div style="margin-top:6px;color:#9ddcff">
                            Value: <span id="challenge_val"><?php echo (int)$challenge; ?></span>
                        </div>

                      
                    </td>
                </tr>

                <!-- NEW BLOCK SLIDER -->
                <tr>
                    <th><label for="ipintel_block_threshold">Block Threshold</label>
                     <p class="description">IPs scoring above this value will be blocked.</p>
                    </th>
                    <td>
                        <input type="range" min="1" max="250" id="ipintel_block_threshold"
                               name="ipintel_block_threshold"
                               value="<?php echo (int)$block; ?>"
                               oninput="document.getElementById('block_val').innerText=this.value">

                        <div style="margin-top:6px;color:#9ddcff">
                            Value: <span id="block_val"><?php echo (int)$block; ?></span>
                        </div>

                       
                    </td>
                </tr>

                <!-- WHITELIST -->
                <tr>
                    <th><label for="ipintel_whitelist">Whitelist IPs</label>
                     <p class="description">One IP per line. These IPs bypass all checks.</p>
                    </th>
                    <td>
                        <textarea id="ipintel_whitelist" name="ipintel_whitelist"
                                  rows="6" style="width:320px;"><?php echo esc_textarea($whitelist); ?></textarea>
                       
                    </td>
                </tr>
         <!-- Blacklist -->       
     		<tr>
                    <th><label for="ipintel_blacklist">Blacklist IPs</label>
                    <p  class="description">One IP per line. These addresses are always blocked immediately.</p>
                    </th>
                    <td>
			<textarea name="ipintel_blacklist"   rows="6" style="width:320px;"><?php
    echo esc_textarea(get_option('ipintel_blacklist', ''));
?></textarea>
			
			</td>
                </tr>


                
<?php $duration = (int) get_option('ipintel_challenge_duration', 10800); ?>

<tr>
    <th scope="row"><label for="ipintel_challenge_duration">Challenge validity</label>
    
   <p class="description"> Defines how long a visitor is allowed to browse your site after successfully completing a challenge.</p>
    
    </th>
    <td>
        <select name="ipintel_challenge_duration">
            <option value="600"   <?php selected($duration, 600); ?>>10 minutes</option>
            <option value="1800"  <?php selected($duration, 1800); ?>>30 minutes</option>
            <option value="3600"  <?php selected($duration, 3600); ?>>1 hour</option>
            <option value="10800" <?php selected($duration, 10800); ?>>3 hours</option>
            <option value="21600" <?php selected($duration, 21600); ?>>6 hours</option>
            <option value="43200" <?php selected($duration, 43200); ?>>12 hours</option>
            <option value="86400" <?php selected($duration, 86400); ?>>24 hours</option>
            <option value="172800"<?php selected($duration, 172800); ?>>48 hours</option>
        </select>
    </td>
</tr>
                
                <tr>
    <th scope="row"><label for="ipintel_challenge_theme">Challenge Theme</label>
    
    <p class="description">Choose how the human verification challenge is displayed to visitors.</p>
    
    </th>
    <td>
<?php $challenge_theme = get_option('ipintel_challenge_theme', 'dark'); ?>

<div class="ipintel-theme-grid">

    <label class="ipintel-theme-card">
        <input type="radio"
               name="ipintel_challenge_theme"
               value="dark"
               <?php checked($challenge_theme, 'dark'); ?>>

        <img src="<?php echo esc_url(IPINTEL_URL); ?>assets/themes/challenge-dark.jpg">
        <span>Dark</span>
    </label>

    <label class="ipintel-theme-card">
        <input type="radio"
               name="ipintel_challenge_theme"
               value="light"
               <?php checked($challenge_theme, 'light'); ?>>

        <img src="<?php echo esc_url(IPINTEL_URL); ?>assets/themes/challenge-light.jpg">
        <span>Light</span>
    </label>

</div>

    </td>
</tr>
<tr>
    <th scope="row"><label for="ipintel_block_theme">Block Page Theme</label>
    
    <p class="description">Select the appearance of the access-denied page shown to blocked visitors.</p>
    
    </th>
    <td>
<?php $block_theme = get_option('ipintel_block_theme', 'dark'); ?>

<div class="ipintel-theme-grid">

    <label class="ipintel-theme-card">
        <input type="radio"
               name="ipintel_block_theme"
               value="dark"
               <?php checked($block_theme, 'dark'); ?>>

        <img src="<?php echo esc_url(IPINTEL_URL); ?>assets/themes/block-dark.jpg">
        <span>Dark</span>
    </label>

    <label class="ipintel-theme-card">
        <input type="radio"
               name="ipintel_block_theme"
               value="light"
               <?php checked($block_theme, 'light'); ?>>

        <img src="<?php echo esc_url(IPINTEL_URL); ?>assets/themes/block-light.jpg">
        <span>Light</span>
    </label>

</div>

    </td>
</tr>

<tr>
  <th scope="row"><label>Footer Badge</label>
      <p class="description" style="margin-top:10px;">
     Display a small security badge in your site footer to signal
active protection against bots, scanners, and abuse.

    </p>
  </th>
  <td>
    <?php $badge = get_option('ipintel_footer_badge', 'off'); ?>

    <fieldset class="ipintel-badge-choices">


      <label class="ipintel-badge-choice">
        <input type="radio" name="ipintel_footer_badge" value="dark" <?php checked($badge, 'dark'); ?>>
        <div class="ipintel-badge-card dark">
          <div class="ipintel-badge-preview">
          <?php // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
          echo  ipintel_badge_logo_svg(); ?>


            <span style="font-size:12px; white-space:nowrap;">Protected by <strong>IPIntel.ai</strong></span>
          </div>
          <div class="ipintel-badge-title">Dark</div>
        </div>
      </label>

      <label class="ipintel-badge-choice">
        <input type="radio" name="ipintel_footer_badge" value="light" <?php checked($badge, 'light'); ?>>
        <div class="ipintel-badge-card light">
          <div class="ipintel-badge-preview">
          <?php // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		 echo  ipintel_badge_logo_svg(); ?>


            <span style="font-size:12px; white-space:nowrap;">Protected by <strong>IPIntel.ai</strong></span>
          </div>
          <div class="ipintel-badge-title">Light</div>
        </div>
      </label>
      
            <label class="ipintel-badge-choice">
        <input type="radio" name="ipintel_footer_badge" value="off" <?php checked($badge, 'off'); ?>>
        <div class="ipintel-badge-card">
          <div class="ipintel-badge-title">Off</div>
          <div class="ipintel-badge-sub">No badge</div>
        </div>
      </label>
    </fieldset>


  </td>
</tr>



            </table>

            <?php submit_button('Save Settings'); ?>
        </form>

    </div> <!-- END MAIN CARD -->



</div> <!-- END wrap -->
<?php
}

