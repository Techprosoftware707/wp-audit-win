<?php
/**
 * Plugin Name: wp-audit-win Lab Fixtures (DO NOT USE IN PRODUCTION)
 * Description: Purpose-built, INERT fixtures for the isolated disposable lab so
 *              the scanner has a detectable "missing capability check" endpoint
 *              to find. Loads ONLY when the WPAWC_LAB constant is defined, so it
 *              cannot accidentally run on a real site.
 *
 * This is a drop-in mu-plugin (wp-content/mu-plugins/) for the throwaway lab in
 * samples/docker-compose.labtarget.yml. It is deliberately a *detection target*,
 * not a working exploit: the insecure PATTERN (a public REST route with no
 * capability check) is present for static/dynamic detection, but the handler
 * returns only a harmless marker — it exposes no data, changes no state, and
 * creates no users. Pair it with the intentionally-outdated WordPress/plugin
 * versions in the lab compose to exercise version-based findings too.
 *
 * @package wp-audit-win-lab-fixtures
 */

defined( 'ABSPATH' ) || exit;

// Safety gate: refuse to do anything unless this is the declared lab.
if ( ! defined( 'WPAWC_LAB' ) || ! WPAWC_LAB ) {
	return;
}

add_action(
	'rest_api_init',
	function () {
		// FIXTURE: a route with NO capability check (permission_callback is open).
		// A correct implementation would require current_user_can(...) here. The
		// scanner should flag this as a missing-authorization REST route. The
		// handler intentionally returns only an inert marker — no real data.
		register_rest_route(
			'wp-audit-lab/v1',
			'/open-endpoint',
			array(
				'methods'             => 'GET',
				'permission_callback' => '__return_true', // <-- intentional weakness (detected)
				'callback'            => function () {
					return array(
						'lab'  => true,
						'note' => 'Intentionally public lab fixture. No sensitive data.',
					);
				},
			)
		);
	}
);
