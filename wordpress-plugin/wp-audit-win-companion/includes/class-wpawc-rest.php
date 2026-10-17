<?php
/**
 * Read-only REST controller.
 *
 * Every route is gated by the `manage_options` capability (site admin). WordPress
 * authenticates the caller (logged-in cookie + nonce, or an Application Password);
 * this controller only authorizes. Nothing here changes site state.
 *
 * @package wp-audit-win-companion
 */

defined( 'ABSPATH' ) || exit;

class WPAWC_Rest {

	/**
	 * Register the routes.
	 */
	public function register_routes() {
		$args = array(
			'permission_callback' => array( $this, 'require_admin' ),
			'methods'             => 'GET',
		);

		register_rest_route(
			WPAWC_REST_NS,
			'/status',
			array_merge( $args, array( 'callback' => array( $this, 'status' ) ) )
		);
		register_rest_route(
			WPAWC_REST_NS,
			'/checks',
			array_merge( $args, array( 'callback' => array( $this, 'checks' ) ) )
		);
		register_rest_route(
			WPAWC_REST_NS,
			'/report',
			array_merge( $args, array( 'callback' => array( $this, 'report' ) ) )
		);
	}

	/**
	 * Authorize: site administrators only.
	 *
	 * @return bool|WP_Error
	 */
	public function require_admin() {
		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}
		return new WP_Error(
			'wpawc_forbidden',
			'This audit endpoint requires the manage_options capability.',
			array( 'status' => rest_authorization_required_code() )
		);
	}

	/**
	 * GET /status — read-only inventory + configuration (unsigned).
	 *
	 * @return WP_REST_Response
	 */
	public function status() {
		return rest_ensure_response( WPAWC_Report::build_data() );
	}

	/**
	 * GET /checks — safe security-configuration checks.
	 *
	 * @return WP_REST_Response
	 */
	public function checks() {
		return rest_ensure_response(
			WPAWC_Checks::evaluate( WPAWC_Checks::collect_env() )
		);
	}

	/**
	 * GET /report — integrity-protected (HMAC-signed) full report.
	 *
	 * @return WP_REST_Response
	 */
	public function report() {
		$key = get_option( WPAWC_KEY_OPTION );
		if ( ! $key ) {
			return new WP_Error(
				'wpawc_no_key',
				'Report key missing; reactivate the plugin.',
				array( 'status' => 500 )
			);
		}
		return rest_ensure_response( WPAWC_Report::build_signed( $key ) );
	}
}
