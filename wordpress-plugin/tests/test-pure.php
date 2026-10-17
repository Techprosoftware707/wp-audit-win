<?php
/**
 * Standalone unit tests for the companion plugin's PURE logic (no WordPress).
 *
 * Run: php wordpress-plugin/tests/test-pure.php
 *
 * Covers the report canonicalization + HMAC signing (integrity / tamper
 * detection) and the security-check evaluation. WordPress functions the pure
 * paths touch are stubbed minimally.
 */

error_reporting( E_ALL );

define( 'ABSPATH', __DIR__ . '/' );   // satisfy the `defined('ABSPATH')` guards
define( 'WPAWC_VERSION', 'test' );

if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $flags = 0 ) {
		return json_encode( $data, $flags );
	}
}

require __DIR__ . '/../wp-audit-win-companion/includes/class-wpawc-checks.php';
require __DIR__ . '/../wp-audit-win-companion/includes/class-wpawc-report.php';

$failures = 0;
function ok( $cond, $msg ) {
	global $failures;
	if ( $cond ) {
		echo "  PASS  $msg\n";
	} else {
		echo "  FAIL  $msg\n";
		$failures++;
	}
}

echo "canonical():\n";
$a = array( 'b' => 1, 'a' => array( 'y' => 2, 'x' => 1 ) );
$b = array( 'a' => array( 'x' => 1, 'y' => 2 ), 'b' => 1 );
ok(
	WPAWC_Report::canonical( $a ) === WPAWC_Report::canonical( $b ),
	'key order does not change the canonical form'
);
$list1 = array( 'l' => array( 3, 1, 2 ) );
$list2 = array( 'l' => array( 3, 1, 2 ) );
ok(
	WPAWC_Report::canonical( $list1 ) === WPAWC_Report::canonical( $list2 ),
	'list order is preserved (not sorted)'
);
ok(
	WPAWC_Report::canonical( array( 'l' => array( 1, 2, 3 ) ) ) !== WPAWC_Report::canonical( $list1 ),
	'different list order yields a different canonical form'
);

echo "sign() integrity:\n";
$key  = 'secret-key-123';
$data = array( 'core' => array( 'version' => '6.4.1' ), 'n' => 2 );
$sig  = WPAWC_Report::sign( $data, $key );
ok(
	$sig === hash_hmac( 'sha256', WPAWC_Report::canonical( $data ), $key ),
	'signature equals HMAC-SHA256 of the canonical body'
);
ok(
	WPAWC_Report::sign( $data, $key ) === $sig,
	'signing is deterministic'
);
$tampered = $data;
$tampered['core']['version'] = '6.4.2';
ok(
	WPAWC_Report::sign( $tampered, $key ) !== $sig,
	'tampering with the body changes the signature'
);
ok(
	WPAWC_Report::sign( $data, 'other-key' ) !== $sig,
	'a different key yields a different signature'
);

echo "evaluate():\n";
$secure = array(
	'force_ssl_admin'          => true,
	'disallow_file_edit'       => true,
	'wp_debug'                 => false,
	'wp_debug_display'         => false,
	'xmlrpc_enabled'           => false,
	'auto_update_core'         => true,
	'custom_table_prefix'      => true,
	'rest_users_requires_auth' => true,
);
$checks = WPAWC_Checks::evaluate( $secure );
ok( count( $checks ) === 8, 'evaluate returns all 8 checks' );
$fails = array_filter( $checks, fn( $c ) => 'fail' === $c['status'] );
ok( count( $fails ) === 0, 'a fully-hardened env has no failing checks' );

$insecure = $secure;
$insecure['wp_debug_display']         = true;
$insecure['rest_users_requires_auth'] = false;
$checks2 = WPAWC_Checks::evaluate( $insecure );
$ids     = array();
foreach ( $checks2 as $c ) {
	if ( 'fail' === $c['status'] ) {
		$ids[] = $c['id'];
	}
}
ok( in_array( 'debug_display_off', $ids, true ), 'debug display on is flagged' );
ok(
	in_array( 'rest_users_requires_auth', $ids, true ),
	'public REST user enumeration is flagged'
);

echo "\n";
if ( $failures ) {
	echo "FAILED: $failures assertion(s)\n";
	exit( 1 );
}
echo "OK: all companion-plugin pure-logic tests passed\n";
