<?php
/*
Plugin Name: Conversion Forwarder
Description: Forwards incoming conversion postbacks to Facebook Conversions API and Google Ads API.
Version: 1.0
Author: RO
*/

// === Register REST Endpoint ===
add_action('rest_api_init', function () {
    register_rest_route('convert/v1', '/forward', array(
        'methods' => 'POST,GET',
        'callback' => 'cf_handle_incoming_conversion',
        'permission_callback' => '__return_true'
    ));
});

/**
 * Handles incoming conversion postbacks and forwards them to Facebook and Google Ads.
 *
 * @param WP_REST_Request $request The REST request object.
 * @return WP_REST_Response The response object containing the status and log.
 */
function cf_handle_incoming_conversion(WP_REST_Request $request)
{
    $params = $request->get_params();
    $log = [];
    $errors = [];
    $timestamp = time();
    $current_time = gmdate("Y-m-d\TH:i:s\Z", $timestamp);

    // Facebook Configs
    $fb_token = get_option('cf_fb_token');
    $pixel_id = get_option('cf_fb_pixel_id');

    // Google Ads Configs
    $google_token = get_option('cf_google_oauth_token');
    $google_dev_token = get_option('cf_google_developer_token');
    $google_cust_id = get_option('cf_google_customer_id');
    $google_action_id = get_option('cf_google_conversion_action_id');

    // === Validate input ===
    if (empty($params['fbclid']) && empty($params['gclid'])) {
        return new WP_REST_Response([
            'status' => 'error',
            'message' => 'Missing required identifier: at least one of fbclid or gclid must be provided.',
        ], 400);
    }

    // === Forward to Facebook ===
    if (!empty($params['fbclid'])) {
        if (!$fb_token || !$pixel_id) {
            $errors['facebook'] = 'Missing Facebook API credentials (token or pixel_id).';
        } else {
            /**
             * Facebook Conversions API does not accept "fbclid" directly inside user_data.
             * Instead, we need to send it as an "fbc" parameter, which is the correctway to pass click identifiers.
             * The expected format for "fbc" is: "fb.1.{unix_timestamp}.{fbclid}"
             * Reference: https://developers.facebook.com/docs/marketing-api/conversions-api/parameters/user-data-parameters/#fbc
             */
            $fb_event = [
                'event_name' => $params['event_name'] ?? 'Lead',
                'event_time' => $timestamp,
                'action_source' => 'website',
                'user_data' => [
                    'fbc' => 'fb.1.' . $timestamp . '.' . $params['fbclid']
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

            if (is_wp_error($fb_response)) {
                $errors['facebook'] = $fb_response->get_error_message();
            } else {
                $fb_body_response = wp_remote_retrieve_body($fb_response);
                $fb_decoded = json_decode($fb_body_response, true);
                if (isset($fb_decoded['error'])) {
                    $errors['facebook'] = $fb_decoded['error'];
                } else {
                    $log['facebook'] = $fb_decoded;
                }
            }
        }
    }

    // === Forward to Google Ads ===
    if (!empty($params['gclid'])) {
        if (!$google_token || !$google_dev_token || !$google_cust_id || !$google_action_id) {
            $errors['google_ads'] = 'Missing Google Ads API credentials (token, dev token, customer id, or conversion action id).';
        } else {
            $google_url = "https://googleads.googleapis.com/v13/customers/{$google_cust_id}:uploadClickConversions";

            $google_body = [
                'customer_id' => $google_cust_id,
                'conversions' => [[
                    'conversion_action' => "customers/{$google_cust_id}/conversionActions/{$google_action_id}",
                    'conversion_date_time' => $current_time,
                    'conversion_value' => isset($params['value']) ? floatval($params['value']) : 0,
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

            if (is_wp_error($google_response)) {
                $errors['google_ads'] = $google_response->get_error_message();
            } else {
                $google_body_response = wp_remote_retrieve_body($google_response);
                $google_decoded = json_decode($google_body_response, true);
                if (isset($google_decoded['error'])) {
                    $errors['google_ads'] = $google_decoded['error'];
                } else {
                    $log['google_ads'] = $google_decoded;
                }
            }
        }
    }

    // === Error Handling ===
    if (!empty($errors)) {
        return new WP_REST_Response([
            'status' => 'error',
            'message' => 'One or more errors occurred during conversion forwarding.',
            'errors' => $errors,
            'log' => $log
        ], 400);
    }

    // === Save to postback log (for admin dashboard) ===
    $client_ip = cf_get_ip();

    $stored_log = get_transient('cf_postback_log');
    if (!$stored_log) {
        $stored_log = [];
    }

    $stored_log[] = [
        'time' => $current_time,
        'ip' => $client_ip,
        'fb' => !empty($params['fbclid']),
        'gclid' => $params['gclid'] ?? '',
        'fbclid' => $params['fbclid'] ?? ''
    ];

    // Keep only last 500 entries
    if (count($stored_log) > 500) {
        $stored_log = array_slice($stored_log, -500);
    }

    // Store the log in a transient for 15 days
    set_transient('cf_postback_log', $stored_log, 15 * DAY_IN_SECONDS);



    // === Return Success Response ===
    return new WP_REST_Response([
        'status' => 'completed',
        'message' => 'Conversion successfully forwarded.',
        'log' => $log
    ], 200);
}

/**
 * Retrieves the client's IP address from various headers.
 *
 * @return string The client's IP address or 'unknown' if not found.
 */
function cf_get_ip()
{
    $headers = [
        'HTTP_CF_CONNECTING_IP',    // Cloudflare
        'HTTP_CLIENT_IP',           // Shared internet
        'HTTP_X_FORWARDED_FOR',     // Proxies
        'REMOTE_ADDR'               // Fallback
    ];

    foreach ($headers as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = $_SERVER[$key];

            // Em caso de múltiplos IPs no X-Forwarded-For, pega o primeiro válido
            if ($key === 'HTTP_X_FORWARDED_FOR') {
                $ip_list = explode(',', $ip);
                foreach ($ip_list as $candidate_ip) {
                    $candidate_ip = trim($candidate_ip);
                    if (filter_var($candidate_ip, FILTER_VALIDATE_IP)) {
                        return $candidate_ip;
                    }
                }
            } else {
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
    }

    return 'unknown';
}

// === Admin Settings Page ===
add_action('admin_menu', function () {
    add_options_page('Conversion Forwarder', 'Conversion Forwarder', 'manage_options', 'conversion_forwarder', 'cf_settings_page');
});

add_action('admin_init', function () {
    register_setting('cf_settings_group', 'cf_fb_token');
    register_setting('cf_settings_group', 'cf_fb_pixel_id');
    register_setting('cf_settings_group', 'cf_google_oauth_token');
    register_setting('cf_settings_group', 'cf_google_developer_token');
    register_setting('cf_settings_group', 'cf_google_customer_id');
    register_setting('cf_settings_group', 'cf_google_conversion_action_id');
});

function cf_settings_page()
{
?>
    <div class="wrap">
        <h1>Conversion Forwarder Settings</h1>
        <p>Configure the settings for forwarding conversions to Facebook and Google Ads.</p>
        <form method="post" action="options.php">
            <?php settings_fields('cf_settings_group'); ?>
            <?php do_settings_sections('cf_settings_group'); ?>
            <h2>Facebook API Settings</h2>
            <p>Read the Facebook Conversions API <a href="https://developers.facebook.com/docs/marketing-api/conversions-api/parameters/" target="_blank" ref="noreferer">documentation</a> for more information on the required parameters.</p>
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
            <p> Read the Google Ads API <a href="https://developers.google.com/google-ads/api/docs/client-libs/dotnet/configuration" target="_blank" ref="noreferer">documentation</a> for more information on the required parameters.</p>
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

            <h2>Endpoint Info</h2>
            <p>Use the following endpoint to send conversion data:</p>
            <pre><?php echo esc_url(rest_url('convert/v1/forward')); ?></pre>
            <p>Example POST data:</p>
            <pre>
{
    "fbclid": "FB.12345",
    "gclid": "EAIaIQob",
    "value": 50,
    "event_name": "Purchase"
}
</pre>
            <?php submit_button(); ?>
        </form>

        <h2>Recent Postbacks (Last 500)</h2>
        <?php
        $log_data = get_transient('cf_postback_log');
        if ($log_data && is_array($log_data)) {
            // Organize log data by date
            $daily_counts = [];

            foreach ($log_data as $entry) {
                $day = substr($entry['time'], 0, 10); // Exemplo: '2025-06-19'
                if (!isset($daily_counts[$day])) {
                    $daily_counts[$day] = ['fb' => 0, 'google' => 0];
                }
                if (!empty($entry['fb'])) {
                    $daily_counts[$day]['fb']++;
                }
                if (!empty($entry['gclid'])) {
                    $daily_counts[$day]['google']++;
                }
            }

            $labels = array_keys($daily_counts);
            $data_fb = array_column($daily_counts, 'fb');
            $data_google = array_column($daily_counts, 'google');
        ?>
            <div style="width:100%; height:300px; margin-bottom:20px;">
                <canvas id="cfPostbackChart"></canvas>
            </div>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <script>
                const ctx = document.getElementById('cfPostbackChart').getContext('2d');
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: <?php echo json_encode($labels); ?>,
                        datasets: [{
                                label: 'Facebook (fbclid)',
                                data: <?php echo json_encode($data_fb); ?>,
                                backgroundColor: '#3b5998'
                            },
                            {
                                label: 'Google (gclid)',
                                data: <?php echo json_encode($data_google); ?>,
                                backgroundColor: '#34a853'
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            x: {
                                stacked: false,
                                title: {
                                    display: true,
                                    text: 'Date'
                                }
                            },
                            y: {
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Number of Postbacks'
                                }
                            }
                        }
                    }
                });
            </script>

            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP</th>
                        <th>fbclid</th>
                        <th>gclid</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach (array_reverse($log_data) as $entry) { ?>
                        <tr>
                            <td><?php echo esc_html($entry['time']); ?></td>
                            <td><?php echo esc_html($entry['ip']); ?></td>
                            <td><?php echo esc_html($entry['fbclid']); ?></td>
                            <td><?php echo esc_html($entry['gclid']); ?></td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
        <?php
        } else {
            echo '<p>No postbacks received yet.</p>';
        }
        ?>

    </div>
<?php
}
