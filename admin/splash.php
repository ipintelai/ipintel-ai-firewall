<?php
if (!defined('ABSPATH')) exit;
?>
<div class="ipintel-card">
    <h2>Connect IPIntel.ai to enable protection</h2>
    <p>
        This site is using the IPIntel AI Firewall plugin, but no API key has been configured yet.
        Create a free IPIntel.ai account to obtain your API key, then paste it into the Settings page.
    </p>
    <p>
        <a class="ipintel-btn" href="https://ipintel.ai/register" target="_blank" rel="noopener">
            Get Free API Key
        </a>
        <a class="ipintel-btn ipintel-btn-secondary"
           href="<?php echo esc_url(admin_url('admin.php?page=ipintel-settings')); ?>">
            Go to Settings
        </a>
    </p>
</div>

