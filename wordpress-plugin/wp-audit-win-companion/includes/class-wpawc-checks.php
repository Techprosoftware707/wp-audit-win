<?php
/**
 * Safe, read-only security-configuration checks.
 *
 * `evaluate()` is a PURE function of an environment array so it is unit-testable
 * without a running WordPress; `collect_env()` gathers that array from the live
 * site. No check changes state or discloses a secret.
 *
 * @package wp-audit-win-companion
 */

defined( 'ABSPATH' ) || exit;

class WPAWC_Checks {

	/**
	 * Evaluate security configuration. PURE: depends only on $env.
	 *
	 * @param array $env Environment booleans/strings (see collect_env()).
	 * @return array List of checks: id,title,status(pass|warn|fail),severity,detail.
	 */
	public static function evaluate( array $env ) {
		$checks = array();

		$checks[] = self::check(
			'ssl_admin',
			'Admin/login served over HTTPS',
			! empty( $env['force_ssl_admin'] ),
			'high',
			'FORCE_SSL_ADMIN keeps credentials off plaintext HTTP.'
		);

		$checks[] = self::check(
			'file_edit_disabled',
			'In-dashboard file editing disabled',
			! empty( $env['disallow_file_edit'] ),
			'medium',
			'DISALLOW_FILE_EDIT blocks theme/plugin code edits from wp-admin.'
		);

		$checks[] = self::check(
			'debug_display_off',
			'Debug output not shown to visitors',
			empty( $env['wp_debug_display'] ),
			'medium',
			'WP_DEBUG_DISPLAY should be false in production to avoid leaking paths.'
		);

		$checks[] = self::check(
			'debug_off',
			'WP_DEBUG disabled in production',
			empty( $env['wp_debug'] ),
			'low',
			'WP_DEBUG on in production risks verbose errors.'
		);

		$checks[] = self::check(
			'xmlrpc_consider_disabling',
			'XML-RPC exposure reviewed',
			empty( $env['xmlrpc_enabled'] ),
			'low',
			'XML-RPC enables brute-force amplification; disable if unused.'
		);

		$checks[] = self::check(
			'auto_update_core',
			'Automatic core updates enabled',
			! empty( $env['auto_update_core'] ),
			'medium',
			'Automatic minor core updates close known holes quickly.'
		);

		$checks[] = self::check(
			'unique_db_prefix',
			'Non-default database table prefix',
			! empty( $env['custom_table_prefix'] ),
			'low',
			'A non-default prefix is minor hardening against some automated tools.'
		);

		$checks[] = self::check(
			'rest_users_requires_auth',
			'REST users route not publicly enumerable',
			! empty( $env['rest_users_requires_auth'] ),
			'medium',
			'An unauthenticated /wp/v2/users list enables username enumeration.'
		);

		return $checks;
	}

	/**
	 * Build a single check result.
	 *
	 * @param string $id       Stable id.
	 * @param string $title    Human title.
	 * @param bool   $ok       Whether the control is in place.
	 * @param string $severity Severity when failing.
	 * @param string $detail   Explanation.
	 * @return array
	 */
	private static function check( $id, $title, $ok, $severity, $detail ) {
		return array(
			'id'       => $id,
			'title'    => $title,
			'status'   => $ok ? 'pass' : 'fail',
			'severity' => $ok ? 'info' : $severity,
			'detail'   => $detail,
		);
	}

	/**
	 * Gather the live environment. Reads only booleans/strings — never secrets.
	 *
	 * @return array
	 */
	public static function collect_env() {
		$prefix_default = ( isset( $GLOBALS['wpdb'] ) && 'wp_' === $GLOBALS['wpdb']->prefix );

		return array(
			'force_ssl_admin'          => ( defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN ) || force_ssl_admin(),
			'disallow_file_edit'       => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
			'wp_debug'                 => defined( 'WP_DEBUG' ) && WP_DEBUG,
			'wp_debug_display'         => defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY,
			'xmlrpc_enabled'           => (bool) apply_filters( 'xmlrpc_enabled', true ),
			'auto_update_core'         => (bool) apply_filters( 'allow_minor_auto_core_updates', true ),
			'custom_table_prefix'      => ! $prefix_default,
			'rest_users_requires_auth' => ! self::rest_users_public(),
		);
	}

	/**
	 * Determine whether the core REST users list is reachable without auth.
	 * Read-only: inspects the filter WordPress itself uses, no HTTP call.
	 *
	 * @return bool True if publicly enumerable.
	 */
	private static function rest_users_public() {
		// WordPress exposes authors with published posts on /wp/v2/users to the
		// public unless a filter restricts it. We treat the presence of a
		// restricting filter as "not public". Conservative default: public.
		return ! has_filter( 'rest_user_query' ) && ! has_filter( 'rest_prepare_user' );
	}
}
