<?php
/*
Plugin Name: Conversion Forwarder
Description: Forwards incoming conversion postbacks to Facebook Conversions API and Google Ads API.
Version: 1.0
Author: RO
*/

// === Register REST Endpoint ===
add_action('rest_api_init', function() {
    register_rest_route('convert/v1', '/forward', array(
        'methods' => 'POST,GET',
        'callback' => 'cf_handle_incoming_conversion',
        'permission_callback' => '__return_true'
    ));
});

function cf_handle_incoming_conversion(WP_REST_Request $request) {
    $params = $request->get_params();
    $log = [];

    // Facebook Configs
    $fb_token = get_option('cf_fb_token');
    $pixel_id = get_option('cf_fb_pixel_id');

    // Google Ads Configs
    $google_token = get_option('cf_google_oauth_token');
    $google_dev_token = get_option('cf_google_developer_token');
    $google_cust_id = get_option('cf_google_customer_id');
    $google_action_id = get_option('cf_google_conversion_action_id');

    $timestamp = time();

    // === Forward to Facebook ===
    if (!empty($params['fbclid']) && $fb_token && $pixel_id) {
        $fb_event = [
            'event_name' => $params['event_name'] ?? 'Lead',
            'event_time' => $timestamp,
            'action_source' => 'website',
            'user_data' => [
                'fbclid' => $params['fbclid']
            ]
        ];

        $fb_body = [
            'data' => [$fb_event],
            'access_token' => $fb_token
        ];

        $fb_response = wp_remote_post("https://graph.facebook.com/v18.0/{$pixel_id}/events", [
            'body' => json_encode($fb_body),
            'headers' => ['Content-Type' => 'application/json'],
            'timeout' => 10
        ]);

        $log['facebook'] = json_decode(wp_remote_retrieve_body($fb_response), true);
    }

    // === Forward to Google Ads ===
    if (!empty($params['gclid']) && $google_token && $google_dev_token && $google_cust_id && $google_action_id) {
        $google_url = "https://googleads.googleapis.com/v13/customers/{$google_cust_id}:uploadClickConversions";

        $google_body = [
            'customer_id' => $google_cust_id,
            'conversions' => [[
                'conversion_action' => "customers/{$google_cust_id}/conversionActions/{$google_action_id}",
                'conversion_date_time' => gmdate("Y-m-d\TH:i:s\Z", $timestamp),
                'conversion_value' => $params['value'] ?? 0,
                'gclid' => $params['gclid']
            ]],
            'partial_failure' => false
        ];

        $google_response = wp_remote_post($google_url, [
            'headers' => [
                'Authorization' => 'Bearer ' . $google_token,
                'Content-Type' => 'application/json',
                'developer-token' => $google_dev_token
            ],
            'body' => json_encode($google_body),
            'timeout' => 10
        ]);

        $log['google_ads'] = json_decode(wp_remote_retrieve_body($google_response), true);
    }

    return new WP_REST_Response([ 'status' => 'completed', 'log' => $log ], 200);
}

// === Admin Settings Page ===
add_action('admin_menu', function() {
    add_options_page('Conversion Forwarder', 'Conversion Forwarder', 'manage_options', 'conversion_forwarder', 'cf_settings_page');
});

add_action('admin_init', function() {
    register_setting('cf_settings_group', 'cf_fb_token');
    register_setting('cf_settings_group', 'cf_fb_pixel_id');
    register_setting('cf_settings_group', 'cf_google_oauth_token');
    register_setting('cf_settings_group', 'cf_google_developer_token');
    register_setting('cf_settings_group', 'cf_google_customer_id');
    register_setting('cf_settings_group', 'cf_google_conversion_action_id');
});

function cf_settings_page() {
    ?>
    <div class="wrap">
        <h1>Conversion Forwarder Settings</h1>
        <form method="post" action="options.php">
            <?php settings_fields('cf_settings_group'); ?>
            <?php do_settings_sections('cf_settings_group'); ?>
            <h2>Facebook API Settings</h2>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Facebook API Token</th>
                    <td><input type="text" name="cf_fb_token" value="<?php echo esc_attr(get_option('cf_fb_token')); ?>" size="60" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Facebook Pixel ID</th>
                    <td><input type="text" name="cf_fb_pixel_id" value="<?php echo esc_attr(get_option('cf_fb_pixel_id')); ?>" /></td>
                </tr>
            </table>

            <h2>Google Ads API Settings</h2>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">OAuth Access Token</th>
                    <td><input type="text" name="cf_google_oauth_token" value="<?php echo esc_attr(get_option('cf_google_oauth_token')); ?>" size="60" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Developer Token</th>
                    <td><input type="text" name="cf_google_developer_token" value="<?php echo esc_attr(get_option('cf_google_developer_token')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Customer ID</th>
                    <td><input type="text" name="cf_google_customer_id" value="<?php echo esc_attr(get_option('cf_google_customer_id')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Conversion Action ID</th>
                    <td><input type="text" name="cf_google_conversion_action_id" value="<?php echo esc_attr(get_option('cf_google_conversion_action_id')); ?>" /></td>
                </tr>
            </table>

            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}