<?php
/**
 * Test helper: sign a JSON body (read from stdin) with the plugin's REAL
 * WPAWC_Report::sign(), using the key from argv[1], and print the hex digest.
 * Used by the backend cross-language interop test (test_companion.py).
 *
 * Usage:  echo '<json>' | php sign-fixture.php <key>
 */

error_reporting( E_ALL );
define( 'ABSPATH', __DIR__ . '/' );
define( 'WPAWC_VERSION', 'test' );

if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $flags = 0 ) {
		return json_encode( $data, $flags );
	}
}

require __DIR__ . '/../wp-audit-win-companion/includes/class-wpawc-report.php';

$key  = isset( $argv[1] ) ? $argv[1] : '';
$data = json_decode( file_get_contents( 'php://stdin' ), true );
echo WPAWC_Report::sign( $data, $key );
