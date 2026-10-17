<?php
/**
 * Audit report builder + integrity signing.
 *
 * `canonical()` and `sign()` are PURE and unit-testable. `build()` assembles the
 * read-only report from the live site. The report contains ONLY versions,
 * flags, counts and configuration — never credentials, salts, keys or PII.
 *
 * @package wp-audit-win-companion
 */

defined( 'ABSPATH' ) || exit;

class WPAWC_Report {

	/**
	 * Deterministic JSON encoding (recursively key-sorted) so the signature is
	 * stable regardless of PHP's associative-array ordering.
	 *
	 * @param mixed $data Data to encode.
	 * @return string
	 */
	public static function canonical( $data ) {
		$data = self::ksort_recursive( $data );
		return wp_json_encode( $data, JSON_UNESCAPED_SLASHES );
	}

	/**
	 * HMAC-SHA256 of the canonical body. The key never leaves the site; only the
	 * resulting hex digest is published, so a consumer can verify integrity
	 * without ever learning the secret.
	 *
	 * @param mixed  $data Report data (without the signature).
	 * @param string $key  Per-site secret.
	 * @return string Hex digest.
	 */
	public static function sign( $data, $key ) {
		return hash_hmac( 'sha256', self::canonical( $data ), (string) $key );
	}

	/**
	 * Recursively sort array keys for a deterministic canonical form.
	 *
	 * @param mixed $value Value.
	 * @return mixed
	 */
	private static function ksort_recursive( $value ) {
		if ( is_array( $value ) ) {
			$is_assoc = array_keys( $value ) !== range( 0, count( $value ) - 1 );
			$out      = array();
			foreach ( $value as $k => $v ) {
				$out[ $k ] = self::ksort_recursive( $v );
			}
			if ( $is_assoc ) {
				ksort( $out );
			}
			return $out;
		}
		return $value;
	}

	/**
	 * Assemble the read-only report data (no signature, no secrets).
	 *
	 * @return array
	 */
	public static function build_data() {
		$theme = wp_get_theme();

		$plugins = array();
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$active  = (array) get_option( 'active_plugins', array() );
		$updates = get_site_transient( 'update_plugins' );
		foreach ( get_plugins() as $file => $meta ) {
			$plugins[] = array(
				'slug'             => dirname( $file ),
				'name'             => isset( $meta['Name'] ) ? $meta['Name'] : '',
				'version'          => isset( $meta['Version'] ) ? $meta['Version'] : '',
				'active'           => in_array( $file, $active, true ),
				'update_available' => isset( $updates->response[ $file ] ),
			);
		}

		return array(
			'report_version' => WPAWC_VERSION,
			'core'           => array(
				'version'          => get_bloginfo( 'version' ),
				'multisite'        => is_multisite(),
				'users'            => (int) count_users()['total_users'], // count only, no names
			),
			'php'            => array(
				'version' => PHP_VERSION,
			),
			'theme'          => array(
				'name'    => $theme ? $theme->get( 'Name' ) : '',
				'version' => $theme ? $theme->get( 'Version' ) : '',
			),
			'plugins'        => $plugins,
			'security'       => WPAWC_Checks::collect_env(),
			'checks'         => WPAWC_Checks::evaluate( WPAWC_Checks::collect_env() ),
		);
	}

	/**
	 * Build the full signed report envelope.
	 *
	 * @param string $key Per-site signing secret.
	 * @return array
	 */
	public static function build_signed( $key ) {
		$data = self::build_data();
		return array(
			'site'         => home_url(),
			'generated_at' => gmdate( 'c' ),
			'algorithm'    => 'HMAC-SHA256',
			'data'         => $data,
			'signature'    => self::sign( $data, $key ),
		);
	}
}
