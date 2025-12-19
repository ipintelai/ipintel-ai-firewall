=== IPIntel AI Firewall ===
Contributors: ipintel
Tags: security, firewall, bot-protection, ip-reputation, anti-spam
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 0.3.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

IP reputation firewall for WordPress using AI-powered threat analysis and automatic request verification.

== Description ==

IPIntel AI Firewall integrates AI-powered IP reputation analysis into WordPress
to help site owners detect and mitigate automated abuse, scanners, and malicious traffic.

Incoming requests are evaluated using external reputation signals and risk scoring.
Based on the assessed risk level, traffic may be allowed, challenged for human verification,
or blocked automatically.

The plugin is designed to be easy to use and does not require custom code or
infrastructure management.

== Features ==

* AI-powered IP reputation and risk scoring
* Automatic allow, challenge, or block decisions
* Human verification challenge for suspicious traffic
* Compatible with aggressive caching environments
* Optional visual security badge
* Simple configuration for non-technical users
* Free API key available with daily request limits

== Installation ==

1. Upload the IPIntel AI Firewall plugin to your WordPress installation, or install it directly from the WordPress plugin directory.
2. Activate the plugin through the “Plugins” menu in WordPress.
3. Go to IPIntel AI → Settings.
4. Enter your IPIntel.ai API key.
5. Configure your preferred challenge duration, themes, and optional settings.
6. Save the settings.

Once activated, the plugin will begin evaluating incoming requests automatically.

Note:
To ensure correct operation under aggressive caching environments (such as LiteSpeed Cache),
the plugin adds a small and limited set of non-invasive rules to the site's .htaccess file.
These rules are removed automatically when the plugin is deactivated.

== FAQ ==

= Does this plugin block visitors automatically? =

The plugin evaluates incoming requests using IP reputation data.
Depending on the assessed risk level, a request may be allowed,
challenged for verification, or blocked automatically.

= What data is sent to the IPIntel.ai service? =

Only the visitor’s IP address is sent to the external service for analysis,
along with the API key used for request authentication.

No WordPress user account data, cookies, or User-Agent information are transmitted.

= Does the plugin work with caching plugins? =

Yes. The plugin is designed to work in environments with aggressive caching,
including LiteSpeed Cache.

To ensure correct behavior, the plugin prevents caching of the challenge
and verification flow using limited .htaccess rules.

= Does the plugin modify my .htaccess file? =

Yes. The plugin adds a small and clearly marked set of non-invasive rules
to prevent caching of the verification process.

These rules do not add redirects, access blocking, or URL rewrite logic,
and are removed automatically when the plugin is deactivated.

= Does the plugin add branding or links to my site? =

No. The plugin does not add any branding or links by default.

An optional footer badge can be enabled manually from the settings page
to display a small visual security indicator. The badge can be disabled at any time.

= Is an API key required? =

Yes. An API key is required for the plugin to function.

A free API key is available with a daily request limit.
Higher request limits require an upgrade.

= Will this plugin slow down my site? =

The plugin performs lightweight IP reputation checks
and is designed to minimize impact on page load times.

Most visitors will not notice any performance difference.

== Data Privacy ==

This plugin connects to the IPIntel.ai API to analyze visitor IP addresses
for security and threat detection purposes.

Data transmitted to the external service:
- Visitor IP address
- API key (used solely for request authentication)

No WordPress user account data, cookies, or User-Agent information are transmitted.

The external service is used exclusively to determine whether a request
should be allowed, challenged, or blocked.

A free API key is available with a daily request limit.
Higher request limits require an upgrade.

Terms of Service: https://ipintel.ai/terms
Privacy Policy: https://ipintel.ai/privacy

== Server Configuration ==

To ensure correct operation under aggressive caching environments
(such as LiteSpeed Cache), this plugin adds a small and limited set
of non-invasive rules to the site's .htaccess file.

These rules:
- Prevent caching of the challenge page
- Prevent caching of the challenge verification endpoint
- Prevent caching until a visitor is verified

No redirects, access blocking, or URL rewrite logic are added.

All rules are clearly marked between:
# BEGIN IPINTEL FIREWALL
# END IPINTEL FIREWALL

The rules are automatically removed when the plugin is deactivated.

== Optional Footer Badge ==

The plugin includes an optional footer badge that can be enabled
from the settings page.

When enabled, the badge displays a small visual indicator showing
that the site is protected by IPIntel.ai.

The badge does not collect data, perform tracking,
or load external resources.

The footer badge is disabled by default and can be turned on or off at any time.

== Third-Party Libraries ==

This plugin bundles the deck.gl JavaScript visualization library.

Library: deck.gl
License: MIT
Source (unminified): https://github.com/visgl/deck.gl
Bundled build: https://unpkg.com/deck.gl@8.8.19/dist.min.js

The bundled file is an unmodified upstream distribution.

== Screenshots ==

1. IPIntel AI Firewall admin dashboard
2. Human verification challenge page
3. Plugin settings page
