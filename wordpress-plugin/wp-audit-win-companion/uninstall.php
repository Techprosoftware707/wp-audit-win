<?php
/**
 * Uninstall cleanup: remove every option this plugin created.
 *
 * Runs only when WordPress itself invokes an uninstall (plugin deleted). Leaves
 * no residual data and touches nothing outside its own options.
 *
 * @package wp-audit-win-companion
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'wpawc_report_key' );
delete_option( 'wpawc_installed_version' );

// Multisite: clean the option on every site.
if ( is_multisite() ) {
	$sites = get_sites( array( 'fields' => 'ids' ) );
	foreach ( (array) $sites as $site_id ) {
		switch_to_blog( (int) $site_id );
		delete_option( 'wpawc_report_key' );
		delete_option( 'wpawc_installed_version' );
		restore_current_blog();
	}
}
