<?php
/**
 * Plugin Name:       wp-audit-win Companion
 * Plugin URI:        https://github.com/techprosoftware707/wp-audit-win
 * Description:       Read-only, capability-restricted audit API for sites you own. Reports core/PHP/plugin/theme and security-configuration information, and runs safe permission/configuration checks. Never creates users, grants privileges, or exposes secrets.
 * Version:           0.1.0
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            wp-audit-win
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-audit-win-companion
 *
 * SECURITY MODEL
 * - Every REST route requires the `manage_options` capability (site admin).
 * - All endpoints are READ-ONLY: they never change site state, create users,
 *   escalate privileges, or install anything.
 * - Reports NEVER include credentials, auth salts/keys, nonces, customer PII,
 *   or order data — only versions, flags, and configuration booleans.
 * - Reports are integrity-protected with an HMAC signature keyed by a secret
 *   generated on activation and stored only in this site's options.
 *
 * @package wp-audit-win-companion
 */

defined( 'ABSPATH' ) || exit;

define( 'WPAWC_VERSION', '0.1.0' );
define( 'WPAWC_REST_NS', 'wp-audit-win/v1' );
define( 'WPAWC_KEY_OPTION', 'wpawc_report_key' );

require_once __DIR__ . '/includes/class-wpawc-checks.php';
require_once __DIR__ . '/includes/class-wpawc-report.php';
require_once __DIR__ . '/includes/class-wpawc-rest.php';

/**
 * Generate the per-site report-signing secret on activation (once).
 *
 * The secret never leaves the site except as the HMAC of a report body, so a
 * consumer can verify integrity without the plugin ever disclosing the key.
 */
function wpawc_activate() {
	if ( ! get_option( WPAWC_KEY_OPTION ) ) {
		$key = function_exists( 'wp_generate_password' )
			? wp_generate_password( 64, true, true )
			: bin2hex( random_bytes( 32 ) );
		// autoload = false: the signing secret is not loaded on every request.
		add_option( WPAWC_KEY_OPTION, $key, '', false );
	}
}
register_activation_hook( __FILE__, 'wpawc_activate' );

/**
 * Register the read-only REST routes.
 */
function wpawc_rest_init() {
	( new WPAWC_Rest() )->register_routes();
}
add_action( 'rest_api_init', 'wpawc_rest_init' );
