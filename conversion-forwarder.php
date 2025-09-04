<?php

/**
 * Plugin Name: Conversion Forwarder
 * Description: Forwards incoming conversion postbacks to Facebook Conversions API and Google Ads API.
 * Version: 1.0
 * Author: RO
 */

// === Register REST Endpoint ===
add_action('rest_api_init', function () {
    register_rest_route('convert/v1', '/forward', [
        'methods' => 'POST,GET',
        'callback' => 'cf_handle_incoming_conversion',
        'permission_callback' => '__return_true', // Public endpoint, security relies on fbclid/gclid and configured API keys.
    ]);
});

/**
 * Retrieves a fresh Google OAuth access token using the refresh token.
 * This token is necessary to authenticate requests to the Google Ads API.
 *
 * @return string|WP_Error The access token string on success, or WP_Error on failure.
 */
function cf_get_fresh_google_access_token()
{
    // Retrieve Google OAuth credentials from WordPress options.
    $client_id = get_option('cf_google_client_id');
    $client_secret = get_option('cf_google_client_secret');
    $refresh_token = get_option('cf_google_refresh_token');

    // Validate if all necessary credentials are provided.
    if (!$client_id || !$client_secret || !$refresh_token) {
        return new WP_Error('missing_credentials', 'Missing Google OAuth credentials (client_id, client_secret, or refresh_token). Please configure them in the plugin settings.');
    }

    // Prepare the request body for the OAuth token endpoint.
    $body = [
        'client_id' => $client_id,
        'client_secret' => $client_secret,
        'refresh_token' => $refresh_token,
        'grant_type' => 'refresh_token',
    ];

    // Make a POST request to Google's OAuth 2.0 token endpoint.
    $response = wp_remote_post('https://oauth2.googleapis.com/token', [
        'body' => $body,
        'timeout' => 10,                                                      // Set a timeout for the API request.
        'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'], // Required for token endpoint.
    ]);

    // Check for WP_Error during the remote request.
    if (is_wp_error($response)) {
        return $response; // Return the error if the request failed.
    }

    // Decode the JSON response body.
    $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

    // Check if the access token is present in the response.
    if (!isset($body_decoded['access_token'])) {
        return new WP_Error('token_error', 'Could not retrieve access token from Google OAuth. Response: ' . json_encode($body_decoded), $body_decoded);
    }

    return $body_decoded['access_token']; // Return the fresh access token.
}

/**
 * Handles incoming conversion postbacks and forwards them to Facebook Conversions API and Google Ads API.
 * This function is the callback for the registered REST API endpoint.
 *
 * @param WP_REST_Request $request The REST request object containing conversion data.
 * @return WP_REST_Response The response object indicating success or failure and logging details.
 */
function cf_handle_incoming_conversion(WP_REST_Request $request)
{
    $params = $request->get_params();               // Get all parameters from the incoming request.
    $log = [];                                   // Initialize array to store successful API responses.
    $errors = [];                                   // Initialize array to store any errors encountered.
    $timestamp = time();                               // Current Unix timestamp for event timing.
    $current_time = gmdate("Y-m-d\TH:i:s\Z", $timestamp); // Formatted time for Google Ads API.

    // Retrieve Facebook API credentials from WordPress options.
    $fb_token = get_option('cf_fb_token');
    $pixel_id = get_option('cf_fb_pixel_id');

    // Retrieve Google Ads API credentials from WordPress options.
    $google_dev_token = get_option('cf_google_developer_token');
    $google_cust_id = get_option('cf_google_customer_id');
    $google_action_id = get_option('cf_google_conversion_action_id');

    // Validate input: At least one of fbclid or gclid must be provided.
    if (empty($params['fbclid']) && empty($params['gclid'])) {
        return new WP_REST_Response([
            'status' => 'error',
            'message' => 'Missing required identifier: at least one of fbclid or gclid must be provided.',
        ], 400); // Bad request status.
    }

    // === Forward to Facebook Conversions API ===
    if (!empty($params['fbclid'])) {
        // Check if Facebook API credentials are set.
        if (!$fb_token || !$pixel_id) {
            $errors['facebook'] = 'Missing Facebook API credentials (token or pixel_id). Please configure them in the plugin settings.';
        } else {
            /**
             * Facebook Conversions API requires 'fbc' parameter for click IDs,
             * formatted as "fb.1.{unix_timestamp}.{fbclid}".
             * Reference: https://developers.facebook.com/docs/marketing-api/conversions-api/parameters/
             */
            $user_data = [
                'fbc' => 'fb.1.' . $timestamp . '.' . sanitize_text_field($params['fbclid']),
            ];

            // Define mapping of incoming request parameters to Facebook user_data fields.
            $facebook_user_fields = [
                'email' => 'em',
                'phone' => 'ph',
                'first_name' => 'fn',
                'last_name' => 'ln',
                'city' => 'ct',
                'state' => 'st',
                'country' => 'country',
                'zip' => 'zp',
                'external_id' => 'external_id',
            ];

            // Process and hash user data for Facebook.
            foreach ($facebook_user_fields as $param_key => $fb_field) {
                if (!empty($params[$param_key])) {
                    // Sanitize and convert to lowercase for consistent hashing.
                    $value = strtolower(trim(sanitize_text_field($params[$param_key])));

                    // Special handling for phone: remove non-digits.
                    if ($param_key === 'phone') {
                        $value = preg_replace('/\D/', '', $value);
                    }

                    // Special handling for country: take first 2 characters for 2-letter code.
                    if ($param_key === 'country') {
                        $value = substr($value, 0, 2);
                    }

                    // Hash the value using SHA256 before sending to Facebook.
                    $user_data[$fb_field] = hash('sha256', $value);
                }
            }

            // Construct the Facebook event payload.
            $fb_event = [
                'event_name' => sanitize_text_field($params['event_name'] ?? 'Lead'), // Default to 'Lead' if not provided.
                'event_time' => $timestamp,
                'action_source' => 'website', // Indicates the event originated from a website.
                'user_data' => $user_data,
            ];

            // Add custom data if provided.
            $custom_data_keys = ['value', 'currency', 'predicted_ltv', 'customer_segmentation', 'content_type', 'content_ids', 'contents', 'event_id'];
            $fb_event['custom_data'] = []; // Initialize custom_data array.
            foreach ($custom_data_keys as $key) {
                if (isset($params[$key])) {
                    $fb_event['custom_data'][$key] = sanitize_text_field($params[$key]);
                }
            }

            // Ensure 'currency' is set, default to 'USD' if not provided.
            if (!empty($fb_event['custom_data']) && !isset($fb_event['custom_data']['currency'])) {
                $fb_event['custom_data']['currency'] = 'USD'; // Default currency.
            }

            // Remove any null or empty values from the event data.
            $fb_event = array_filter($fb_event, function ($value) {
                return !is_null($value) && $value !== '' && $value !== [];
            });

            // Construct the full Facebook API request body.
            $fb_body = [
                'data' => [$fb_event],
                'access_token' => $fb_token,
            ];

            // Make the POST request to Facebook Conversions API.
            $fb_response = wp_remote_post("https://graph.facebook.com/v18.0/{$pixel_id}/events", [
                'body' => json_encode($fb_body),
                'headers' => ['Content-Type' => 'application/json'],
                'timeout' => 10,
            ]);

            // Handle Facebook API response.
            if (is_wp_error($fb_response)) {
                $errors['facebook'] = $fb_response->get_error_message();
            } else {
                $fb_body_response = wp_remote_retrieve_body($fb_response);
                $fb_decoded = json_decode($fb_body_response, true);
                if (isset($fb_decoded['error'])) {
                    $errors['facebook'] = $fb_decoded['error']['message'] ?? json_encode($fb_decoded['error']);
                } else {
                    $log['facebook'] = $fb_decoded; // Log successful response.
                }
            }
        }
    }

    // === Forward to Google Ads API ===
    if (!empty($params['gclid'])) {
        // Retrieve a fresh Google OAuth access token.
        $access_token = cf_get_fresh_google_access_token();

        // Check for errors in obtaining the access token or missing Google Ads credentials.
        if (is_wp_error($access_token)) {
            $errors['google_ads'] = $access_token->get_error_message();
        } elseif (!$google_dev_token || !$google_cust_id || !$google_action_id) {
            $errors['google_ads'] = 'Missing Google Ads API credentials (developer token, customer id, or conversion action id). Please configure them in the plugin settings.';
        } else {
            // Construct the Google Ads API URL.
            $google_url = "https://googleads.googleapis.com/v13/customers/{$google_cust_id}:uploadClickConversions";

            // Construct the conversion object for Google Ads.
            $conversion = [
                'conversion_action' => "customers/{$google_cust_id}/conversionActions/{$google_action_id}",
                'conversion_date_time' => $current_time,                                            // Event time in required format.
                'gclid' => sanitize_text_field($params['gclid']),                    // Google Click Identifier.
                'conversion_value' => isset($params['value']) ? floatval($params['value']) : 0, // Conversion value, default to 0.
                'currency_code' => 'USD',                                                    // Default currency code. This could be made configurable if needed.
            ];

            // Construct the full Google Ads API request body.
            $google_body = [
                'customer_id' => $google_cust_id,
                'conversions' => [$conversion], // Array of conversions.
                'partial_failure' => false,         // Set to false to fail the entire request if any conversion fails.
            ];

            // Make the POST request to Google Ads API.
            $google_response = wp_remote_post($google_url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $access_token,
                    'Content-Type' => 'application/json',
                    'developer-token' => $google_dev_token,
                ],
                'body' => json_encode($google_body),
                'timeout' => 10,
            ]);

            // Handle Google Ads API response.
            if (is_wp_error($google_response)) {
                $errors['google_ads'] = $google_response->get_error_message();
            } else {
                $google_body_response = wp_remote_retrieve_body($google_response);
                $google_decoded = json_decode($google_body_response, true);

                // Check for 'error' key in Google Ads response.
                if (isset($google_decoded['error'])) {
                    $errors['google_ads'] = $google_decoded['error']['message'] ?? json_encode($google_decoded['error']);
                } else {
                    $log['google_ads'] = $google_decoded; // Log successful response.
                }
            }
        }
    }

    // === Final Response & Error Handling ===
    if (!empty($errors)) {
        return new WP_REST_Response([
            'status' => 'error',
            'message' => 'One or more errors occurred during conversion forwarding. Check the "errors" field for details.',
            'errors' => $errors,
            'log' => $log, // Still show successful logs even if some errors occurred.
        ], 400);           // Return 400 Bad Request if there were errors.
    }

    // === Save to Postback Log ===
    $entry = [
        'time' => $current_time,
        'ip' => cf_get_ip(),
        'gclid' => sanitize_text_field($params['gclid'] ?? ''),
        'fbclid' => sanitize_text_field($params['fbclid'] ?? ''),
        'parameters' => $params, // Store all incoming parameters for debugging.
    ];

    // Store the log entry in the postback log.
    cf_store_log_entry($entry);

    // Return successful response.
    return new WP_REST_Response([
        'status' => 'completed',
        'message' => 'Conversion successfully forwarded.',
        'log' => $log,
    ], 200); // OK status.
}

// === Utils ===

/**
 * Stores a log entry in the postback log transient.
 * This function is used to keep track of successful postbacks for debugging and monitoring.
 *
 * @param array $entry The log entry to store, should include 'time', 'ip', 'gclid', 'fbclid', and 'parameters'.
 */
function cf_store_log_entry($entry)
{
    // Retrieve existing log entries from option.
    $stored_log = get_option('cf_postback_log');

    // If no log exists or it's not an array, initialize it.
    if (!is_array($stored_log)) {
        $stored_log = [];
    }

    // Fallback for older versions of the plugin.
    // Old logs were stored in a transient, but now we use an option.
    if (empty($stored_log)) {
        $stored_log = get_transient('cf_postback_log');
        if (!is_array($stored_log)) {
            $stored_log = [];
        }
    }

    // Add the new entry to the log.
    $stored_log[] = $entry;

    // Limit the log to the last 500000 entries (or any other reasonable limit).
    if (count($stored_log) > 500000) {
        $stored_log = array_slice($stored_log, -500000);
    }

    // Save the updated log back to the option.
    update_option('cf_postback_log', $stored_log);
}

/**
 * Retrieves the postback log from the transient.
 * This function is used to display the log entries on the admin settings page.
 *
 * @return array The postback log entries, reversed to show the most recent first.
 */
function cf_get_postback_log()
{
    // Retrieve the postback log from the option.
    $log_data = get_option('cf_postback_log');

    // If log data is not an array, initialize it.
    if (!is_array($log_data)) {
        $log_data = [];
    }

    // Fallback for older versions of the plugin.
    // Old logs were stored in a transient, but now we use an option.
    if (empty($log_data)) {
        $log_data = get_transient('cf_postback_log');
        if (!is_array($log_data)) {
            $log_data = [];
        }
    }

    // Reverse the log data to show the most recent first.
    $log_data = array_reverse($log_data);

    // Return the log data.
    return $log_data;
}

/**
 * Sorts log entries by date in descending order.
 *
 * @param array $logs The log entries to sort.
 * @return array The sorted log entries.
 */
function cf_sort_logs_by_date($logs)
{
    usort($logs, function ($a, $b) {
        return strtotime($b['time']) - strtotime($a['time']);
    });
    return $logs;
}

/**
 * Filters log entries based on a search term.
 * The search term is matched against the 'ip', 'fbclid', 'gclid', and 'parameters' fields.
 *
 * @param array $logs The log entries to filter.
 * @param string $search_term The term to search for within the log entries.
 * @return array The filtered log entries that match the search term.
 */
function cf_search_logs($logs, $search_term) {
    if (!empty($search_term)) {
        $keep = [];
        for ($i = 0; $i < count($logs); $i++) {
            if (
                stripos($logs[$i]['ip'], $search_term) !== false ||
                stripos($logs[$i]['fbclid'], $search_term) !== false ||
                stripos($logs[$i]['gclid'], $search_term) !== false ||
                stripos(strip_tags(cf_prettify_parameters($logs[$i]['parameters'], false)), $search_term) !== false ||
                stripos(json_encode($logs[$i]['parameters']), $search_term) !== false
            ) {
                $keep[] = $logs[$i];
            }
        }
            $logs = cf_sort_logs_by_date($keep);
        }

    return $logs;
}

/**
 * Prints a formatted view of the parameters for easier visualization.
 * 
 * @param array $params The parameters to print.
 * @param bool $echo Whether to echo the output directly or return it as a string. Default is true (echo).
 * 
 * @return string|null The formatted parameters as a string if $echo is false, otherwise null.
 */
function cf_prettify_parameters($params, $echo = true)
{
    $output = '<div class="cf-parameters">';
    // Print a nice view for a single hierarchical JSON structure.
    // So { prop : value } will be <p><strong></strong>prop</strong>: value</p>
    // Value will be a <pre></pre> block for better readability.
    foreach ($params as $key => $value) {
        if (is_bool($value)) {
            $output .= '<p><strong>' . esc_html($key) . '</strong>: ' . ($value == true ? 'true' : 'false') . '</p>';
        } else if (is_array($value) || is_object($value)) {
            $output .= '<p><strong>' . esc_html($key) . '</strong>: <pre>' . esc_html(json_encode($value, JSON_PRETTY_PRINT)) . '</pre></p>';
        } else {
            $output .= '<p><strong>' . esc_html($key) . '</strong>: <span>' . esc_html($value) . '</span></p>';
        }
    }

    $output = $output . '</div>';

    if ($echo) {
        echo $output;
    } else {
        return $output;
    }
}

/**
 * Retrieves the client's IP address from various common headers.
 * Prioritizes headers that are likely to contain the real client IP (e.g., Cloudflare).
 *
 * @return string The client's IP address or 'unknown' if not found or invalid.
 */
function cf_get_ip()
{
    $headers = [
        'HTTP_CF_CONNECTING_IP', // Cloudflare specific header
        'HTTP_CLIENT_IP',        // Often used by proxies
        'HTTP_X_FORWARDED_FOR',  // Standard for proxies, can contain multiple IPs
        'REMOTE_ADDR',           // The IP address of the server directly connecting
    ];

    foreach ($headers as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = sanitize_text_field($_SERVER[$key]); // Sanitize the header value.

            // Handle multiple IPs in X-Forwarded-For (take the first valid one).
            if ($key === 'HTTP_X_FORWARDED_FOR') {
                $ip_list = explode(',', $ip);
                foreach ($ip_list as $candidate_ip) {
                    $candidate_ip = trim($candidate_ip);
                    if (filter_var($candidate_ip, FILTER_VALIDATE_IP)) {
                        return $candidate_ip;
                    }
                }
            } else {
                // For other headers, validate directly.
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
    }

    return 'unknown'; // Return 'unknown' if no valid IP is found.
}

/**
 * Check if we are on the plugin's admin page.
 *
 * @return bool True if on the plugin's admin page, false otherwise.
 */
function cf_is_admin_page() {
    if (isset($_GET['page']) && $_GET['page'] === 'conversion_forwarder') {
        return true;
    }
    return false;
}

/**
 * Retrieves the current pagination number from the query parameters.
 *
 * @return int The current pagination number.
 */
function cf_get_current_log_page() {
    $pagination = isset($_GET['pbpage']) ? intval($_GET['pbpage']) : 1; // Get current page number.
    return $pagination;
}

/**
 * Retrieves the current search query from the query parameters.
 *
 * @return string The current search query.
 */
function cf_get_search_query() {
    $search_query = isset($_GET['search']) ? trim(sanitize_text_field($_GET['search'])) : ''; // Search query.
    $search_query = str_replace(['\"', '\"'], ['"', '"'], $search_query);
    return $search_query;
}

/**
 * Escape a value for CSV
 */
function cf_csv_escape($value) {
    // Convert non-scalar to JSON
    if (is_array($value) || is_object($value)) {
        $value = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    // Ensure string
    $value = (string) $value;
    // Escape internal quotes
    $value = str_replace('"', '""', $value);
    // Wrap in quotes always (safe for commas/semicolons/newlines)
    return '"' . $value . '"';
}

// === Data Export ===

/**
 * Handle email export action
 */
function cf_export_emails() {
    // Check user permissions
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }

    // Allow filtering the logs a search parameter
    $search_query = cf_get_search_query(); // Get current search query.
    $log_data = cf_get_postback_log();
    if (!empty($search_query)) {
        $log_data = cf_search_logs($log_data, $search_query);
    }

    // Get the email addresses from the database
    $emails = [];
    foreach ($log_data as $entry) {
        // Look for email in parameters
        if (isset($entry['parameters']['email'])) {
            $emails[] = sanitize_email($entry['parameters']['email']);
        }
        // Also check for 'em' parameter which might be an array of emails
        else if (isset($entry['parameters']['em']) && is_array($entry['parameters']['em'])) {
            foreach ($entry['parameters']['em'] as $email) {
                $emails[] = sanitize_email($email);
            }
        }
        // Attempt to extract an email from any other parameter
        else {
            $param_string = json_encode($entry['parameters']);
            if (preg_match_all('/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/', $param_string, $matches)) {
                foreach ($matches[0] as $email) {
                    $emails[] = sanitize_email($email);
                }
            }
        }
    }

    // Remove duplicates and empty values
    $emails = array_unique(array_filter($emails));
    sort($emails);

    // Prepare CSV content
    $csv_content = "Email\n" . implode("\n", $emails);
    $filename = 'exported_emails_' . date('Y-m-d_H-i-s') . '.csv';

    // Send headers to prompt file download
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo $csv_content;
    exit;
}
add_action('admin_init', function() {
    if (cf_is_admin_page() && isset($_GET['action']) && $_GET['action'] === 'export_emails') {
        cf_export_emails();
    }
});

/**
 * Handle log export action
 */
/**
 * Handle log export action
 */
function cf_export_logs() {
    // Check user permissions
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }

    // Allow filtering the logs a search parameter
    $search_query = cf_get_search_query(); // Get current search query.
    $log_data = cf_get_postback_log();
    if (!empty($search_query)) {
        $log_data = cf_search_logs($log_data, $search_query);
    }

    // Prepare CSV content
    $csv_content = "Time,IP,FBCLID,GCLID,Parameters,Raw Parameters\n";

    foreach ($log_data as $entry) {
        $time  = cf_csv_escape($entry['time']);
        $ip    = cf_csv_escape($entry['ip']);
        $fbclid = cf_csv_escape($entry['fbclid']);
        $gclid  = cf_csv_escape($entry['gclid']);

        // Friendly parameters
        $param_pairs = [];
        foreach ($entry['parameters'] as $key => $value) {
            if (is_array($value)) {
                $value = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            }
            $param_pairs[] = "$key=$value";
        }
        $parameters = cf_csv_escape(implode("; ", $param_pairs));

        // Raw JSON parameters
        $raw_parameters = cf_csv_escape(
            json_encode($entry['parameters'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
        );

        $csv_content .= implode(",", [
            $time,
            $ip,
            $fbclid,
            $gclid,
            $parameters,
            $raw_parameters
        ]) . "\n";
    }

    $filename = 'postback_logs_' . date('Y-m-d_H-i-s') . '.csv';

    // Send headers to prompt file download
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo $csv_content;
    exit;
}
add_action('admin_init', function() {
    if (cf_is_admin_page() && isset($_GET['action']) && $_GET['action'] === 'export_logs') {
        cf_export_logs();
    }
});

// === Admin Settings Page ===
// Add an options page under the 'Settings' menu in the WordPress admin.
add_action('admin_menu', function () {
    add_options_page(
        'Conversion Forwarder', // Page title
        'Conversion Forwarder', // Menu title
        'manage_options',       // Capability required to access
        'conversion_forwarder', // Menu slug
        'cf_settings_page'      // Callback function to render the page
    );
});

// Register plugin settings to be handled by WordPress.
add_action('admin_init', function () {
    register_setting('cf_settings_group', 'cf_fb_token');
    register_setting('cf_settings_group', 'cf_fb_pixel_id');
    register_setting('cf_settings_group', 'cf_google_client_id');
    register_setting('cf_settings_group', 'cf_google_client_secret');
    register_setting('cf_settings_group', 'cf_google_refresh_token');
    register_setting('cf_settings_group', 'cf_google_developer_token');
    register_setting('cf_settings_group', 'cf_google_customer_id');
    register_setting('cf_settings_group', 'cf_google_conversion_action_id');
    register_setting('cf_settings_group', 'cf_postback_filter');
});

/**
 * Renders the admin settings page for the Conversion Forwarder plugin.
 * This includes input fields for API credentials and a display of recent postbacks.
 */
function cf_settings_page()
{
?>
    <style>
        .cf-parameters {
            max-height: 150px;
            overflow: auto;
        }

        .cf-parameters p {
            margin-bottom: 0 !important;
            white-space: nowrap;
        }

        .cf-parameters span {
            white-space: nowrap;
        }
    </style>
    <div class="wrap">
        <h1>Conversion Forwarder Settings</h1>
        <p>Configure the settings for forwarding conversions to Facebook and Google Ads.</p>
        <form method="post" action="options.php">
            <?php
            settings_fields('cf_settings_group');
            do_settings_sections('cf_settings_group');
            ?>

            <h2>Facebook API Settings</h2>
            <p>Read the Facebook Conversions API <a
                    href="https://developers.facebook.com/docs/marketing-api/conversions-api/parameters/" target="_blank"
                    rel="noreferrer noopener">documentation</a> for more information on the required parameters.</p>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Facebook API Token</th>
                    <td><input type="text" name="cf_fb_token" value="<?php echo esc_attr(get_option('cf_fb_token')); ?>"
                            size="60" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Facebook Pixel ID</th>
                    <td><input type="text" name="cf_fb_pixel_id"
                            value="<?php echo esc_attr(get_option('cf_fb_pixel_id')); ?>" /></td>
                </tr>
            </table>

            <h2>Google OAuth Settings (for Automatic Token Refresh)</h2>
            <p>These credentials are used to obtain an access token for the Google Ads API. For more information on setting
                up OAuth, refer to the Google Ads API <a
                    href="https://developers.google.com/google-ads/api/docs/oauth/overview" target="_blank"
                    rel="noreferrer noopener">documentation</a>.</p>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Google OAuth Client ID</th>
                    <td><input type="text" name="cf_google_client_id"
                            value="<?php echo esc_attr(get_option('cf_google_client_id')); ?>" size="60" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Google OAuth Client Secret</th>
                    <td><input type="text" name="cf_google_client_secret"
                            value="<?php echo esc_attr(get_option('cf_google_client_secret')); ?>" size="60" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Google OAuth Refresh Token</th>
                    <td><input type="text" name="cf_google_refresh_token"
                            value="<?php echo esc_attr(get_option('cf_google_refresh_token')); ?>" size="60" /></td>
                </tr>
            </table>

            <h2>Google Ads API Settings</h2>
            <p>These are specific to your Google Ads account. Refer to the Google Ads API <a
                    href="https://developers.google.com/google-ads/api/docs/conversions/overview" target="_blank"
                    rel="noreferrer noopener">documentation</a> for details on conversion actions.</p>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Developer Token</th>
                    <td><input type="text" name="cf_google_developer_token"
                            value="<?php echo esc_attr(get_option('cf_google_developer_token')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Customer ID (without hyphens)</th>
                    <td><input type="text" name="cf_google_customer_id"
                            value="<?php echo esc_attr(get_option('cf_google_customer_id')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Conversion Action ID</th>
                    <td><input type="text" name="cf_google_conversion_action_id"
                            value="<?php echo esc_attr(get_option('cf_google_conversion_action_id')); ?>" /></td>
                </tr>
            </table>

            <h2>Postback Logs Preview</h2>
            <p>Preview and filter the postbacks logs.<br><strong>Note:</strong> <em>This does not affect the data sent to
                    the endpoint, only the logs displayed here.</em></p>

            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Strings to Remove (comma-separated)</th>
                    <td><input type="text" name="cf_postback_filter"
                            value="<?php echo esc_attr(get_option('cf_postback_filter')); ?>" /></td>
                </tr>
            </table>

            <?php submit_button(); ?>

            <hr>

            <h2>Endpoint Information</h2>
            <p>Send your conversion data to the following endpoint:</p>
            <pre><code><?php echo esc_url(rest_url('convert/v1/forward')); ?></code></pre>
            <p>Example POST/GET data (JSON for POST, query parameters for GET):</p>
            <pre>
                    {
                        "fbclid": "ABCD1234567890EFGHIJ",
                        "gclid": "EAIaIQobABCD1234567890EFGHIJ",
                        "value": 50.00,
                        "event_name": "Purchase",
                        "email": "test@example.com",
                        "phone": "+1234567890",
                        "first_name": "John",
                        "last_name": "Doe",
                        "city": "Anytown",
                        "state": "CA",
                        "country": "US",
                        "zip": "90210",
                        "external_id": "user123"
                    }
                    </pre>
        </form>

        <hr>

        <h2>Recent Postbacks (Unique gclids/fbclids)</h2>

        <?php
        // Retrieve the transient log data.
        $log_data = cf_get_postback_log();

        if ($log_data && is_array($log_data)) {
            $daily_fbclids = [];
            $daily_gclids = [];

            // Sanitize and filter out unwanted strings
            $filter_strings = explode(',', get_option('cf_postback_filter', ''));
            $filter_strings = array_map('trim', $filter_strings);

            foreach ($log_data as $i => $entry) {
                $continue = true;

                // Check if any of the filter strings are present in the entry string.
                $entry_string = json_encode($entry); // Convert entry to string for filtering.
                foreach ($filter_strings as $filter) {
                    if (strpos($entry_string, $filter) !== false) {
                        unset($log_data[$i]); // Remove the entry if it contains any filter string.
                        $continue = false;    // If any filter string is found, skip this entry.
                    }
                }

                // Skip this entry if it contains any filter string.
                if (!$continue) {
                    continue;
                }

                $day = substr($entry['time'], 0, 10);

                if (!isset($daily_fbclids[$day])) {
                    $daily_fbclids[$day] = [];
                }
                if (!isset($daily_gclids[$day])) {
                    $daily_gclids[$day] = [];
                }

                if (!empty($entry['fbclid'])) {
                    $daily_fbclids[$day][$entry['fbclid']] = true;
                }
                if (!empty($entry['gclid'])) {
                    $daily_gclids[$day][$entry['gclid']] = true;
                }
            }

            $all_days = array_unique(array_merge(array_keys($daily_fbclids), array_keys($daily_gclids)));
            sort($all_days);

            $labels = $all_days;
            $data_fb = [];
            $data_google = [];

            foreach ($all_days as $day) {
                $data_fb[] = isset($daily_fbclids[$day]) ? count($daily_fbclids[$day]) : 0;
                $data_google[] = isset($daily_gclids[$day]) ? count($daily_gclids[$day]) : 0;
            }
        ?>
            <div style="width:100%; height:300px; margin-bottom:20px;">
                <canvas id="cfPostbackChart"></canvas>
            </div>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    const ctx = document.getElementById('cfPostbackChart');
                    if (ctx) { // Ensure canvas element exists
                        new Chart(ctx.getContext('2d'), {
                            type: 'bar',
                            data: {
                                labels: <?php echo json_encode($labels); ?>,
                                datasets: [{
                                        label: 'Facebook (fbclid)',
                                        data: <?php echo json_encode($data_fb); ?>,
                                        backgroundColor: '#3b5998',
                                        borderColor: '#3b5998',
                                        borderWidth: 1
                                    },
                                    {
                                        label: 'Google (gclid)',
                                        data: <?php echo json_encode($data_google); ?>,
                                        backgroundColor: '#34a853',
                                        borderColor: '#34a853',
                                        borderWidth: 1
                                    }
                                ]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false, // Allow canvas to resize freely within its container
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
                                        },
                                        ticks: {
                                            precision: 0 // Ensure Y-axis ticks are integers
                                        }
                                    }
                                },
                                plugins: {
                                    legend: {
                                        position: 'top',
                                    },
                                    title: {
                                        display: true,
                                        text: 'Daily Conversion Postbacks'
                                    }
                                }
                            }
                        });
                    }
                });
            </script>

            <h2 id="recent-postbacks">Recent Postbacks (Log)</h2>

            <div class="cf-row" style="display: flex;grid-template-columns: 1fr 1fr;justify-content: space-between;">
                <div class="row">
                    <?php

                    $search_query = cf_get_search_query(); // Get current search query.
                    $pagination = cf_get_current_log_page(); // Get current page number.

                    // Allow to search within the log data.
                    if (!empty($search_query)) {
                        $log_data = cf_search_logs($log_data, $search_query);
                    }
                    ?>

                    <form method="GET" action="<?php echo admin_url('/options-general.php#conversion-log') ?>">
                        <input type="hidden" name="page" value="conversion_forwarder" />
                        <input type="text" name="search" value="<?php echo esc_attr($search_query); ?>"
                            placeholder="Search..." />
                        <input type="submit" value="Search" class="button" />
                    </form>
                </div>

                <div class="row">
                    <a href="<?php echo esc_url_raw(admin_url('/options-general.php?page=conversion_forwarder&action=export_logs&search=' . $search_query)) ?>" class="button"><?php echo __('Export Logs') ?></a>
                    <p style="margin-top: 3px; font-size: 10px;">Search query will be applied to the exported logs.</p>
                </div>

                <div class="row">
                    <a href="<?php echo esc_url_raw(admin_url('/options-general.php?page=conversion_forwarder&action=export_emails&search=' . $search_query)) ?>" class="button"><?php echo __('Export Emails') ?></a>
                    <p style="margin-top: 3px; font-size: 10px;">Search query will be applied to the exported emails.</p>
                </div>

                <?php
                // Allow external plugins to match logs by providing a list of ips they want to match
                // The IPs should be sent as an array
                $ips_sources = array_unique(apply_filters('conversion_forwarder_ips_sources', []));
                $ips_to_match = array_unique(apply_filters('conversion_forwarder_ips_to_match', []));

                if (!empty($ips_sources) && is_array($ips_sources)) {
                    $is_filter_active = !empty($_GET['filter_ips_by_sources']) && $_GET['filter_ips_by_sources'];

                    $filter_by_ip_url = add_query_arg('filter_ips_by_sources', true, admin_url('/options-general.php#conversion-log'));
                    $filter_by_ip_url = add_query_arg('page', 'conversion_forwarder', $filter_by_ip_url);
                    $filter_by_ip_url = add_query_arg('pbpage', $pagination, $filter_by_ip_url);
                    $sources = "(" . implode(',', $ips_sources) . ")";

                    $btn_text = $is_filter_active ? 'Disable Filter by IP Sources' : 'Filter by IP Sources';
                    if ($is_filter_active) {
                        $filter_by_ip_url = remove_query_arg('filter_ips_by_sources', $filter_by_ip_url);
                        $filter_by_ip_url = remove_query_arg('pbpage', $filter_by_ip_url);
                    }
                ?>
                    <div class="row">
                        <a href="<?php echo esc_url_raw($filter_by_ip_url) ?>" class="button"><?php echo $btn_text; ?></a>
                        <p style="margin-top: 3px; font-size: 10px;"><?php echo $sources; ?> - Total of
                            <?php echo count($ips_to_match); ?> IPs.
                        </p>
                    </div>
                <?php

                    // Filter logs by IP sources
                    if (!empty($_GET['filter_ips_by_sources'])) {
                        $keep = [];

                        // Optimize: create a hash map for quick IP lookups
                        $ips_to_match_map = array_flip($ips_to_match);

                        // Iterate through the log data once
                        foreach ($log_data as $entry) {
                            // Check if the log entry's IP exists in our map
                            if (isset($entry['ip']) && isset($ips_to_match_map[$entry['ip']])) {
                                $keep[] = $entry;
                            }
                        }

                        $log_data = cf_sort_logs_by_date($keep);
                    }
                }
                ?>
            </div>

            <?php
            $items_per_page = 100;

            // Paginate the log data.
            $total_items = count($log_data);
            $total_pages = ceil($total_items / $items_per_page);
            $offset = ($pagination - 1) * $items_per_page;

            $log_data = array_slice($log_data, $offset, $items_per_page);
            ?>

            <?php if ($total_items > 0) { ?>
                <p>Displaying page <?php echo $pagination; ?> of <?php echo $total_pages; ?>. Total postbacks:
                    <?php echo $total_items; ?>.
                </p>
            <?php } else { ?>
                <p>No postbacks found.</p>
            <?php } ?>

            <table class="widefat fixed striped" id="conversion-log">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP</th>
                        <th>fbclid</th>
                        <th>gclid</th>
                        <th>Parameters</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($log_data as $entry) {
                    ?>
                        <tr>
                            <td><?php echo esc_html($entry['time']); ?></td>
                            <td><?php echo esc_html($entry['ip']); ?></td>
                            <td><?php echo esc_html($entry['fbclid']); ?></td>
                            <td><?php echo esc_html($entry['gclid']); ?></td>
                            <td><?php echo cf_prettify_parameters($entry['parameters']); ?></td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>

            <?php
            // Display pagination links.
            if ($total_pages > 1) {
                echo '<div class="tablenav" style="text-align: center;">';

                $window = 10; // how many pages to show around the current
                $max_visible = 30; // threshold for collapsing

                // Add search query to pagination links if present
                $search_param = !empty($search_query) ? '&search=' . urlencode($search_query) : '';

                // Show all pages if within max_visible limit
                if ($total_pages <= $max_visible) {
                    for ($i = 1; $i <= $total_pages; $i++) {
                        if ($i === $pagination) {
                            echo '<span class="tablenav-page tablenav-page-current" style="margin-left: 5px;">' . $i . '</span>';
                        } else {
                            echo '<a class="tablenav-page" href="?page=conversion_forwarder&pbpage=' . $i . $search_param . '#recent-postbacks" style="margin-left: 5px;">' . $i . '</a>';
                        }
                    }
                }
                // Show a moving window of pages
                else {
                    // Always show first page
                    if ($pagination == 1) {
                        echo '<span class="tablenav-page tablenav-page-current" style="margin-left: 5px;">1</span>';
                    } else {
                        echo '<a class="tablenav-page" href="?page=conversion_forwarder&pbpage=1#recent-postbacks" style="margin-left: 5px;">1</a>';
                    }

                    // Add "..." if current is far from start
                    if ($pagination > ($window + 2)) {
                        echo '<span style="margin-left: 5px;">...</span>';
                    }

                    // Middle pages around current
                    $start = max(2, $pagination - $window);
                    $end = min($total_pages - 1, $pagination + $window);

                    for ($i = $start; $i <= $end; $i++) {
                        if ($i === $pagination) {
                            echo '<span class="tablenav-page tablenav-page-current" style="margin-left: 5px;">' . $i . '</span>';
                        } else {
                            echo '<a class="tablenav-page" href="?page=conversion_forwarder&pbpage=' . $i . '#recent-postbacks" style="margin-left: 5px;">' . $i . '</a>';
                        }
                    }

                    // Add "..." if current is far from end
                    if ($pagination < $total_pages - ($window + 1)) {
                        echo '<span style="margin-left: 5px;">...</span>';
                    }

                    // Always show last page
                    if ($pagination == $total_pages) {
                        echo '<span class="tablenav-page tablenav-page-current" style="margin-left: 5px;">' . $total_pages . '</span>';
                    } else {
                        echo '<a class="tablenav-page" href="?page=conversion_forwarder&pbpage=' . $total_pages . '#recent-postbacks" style="margin-left: 5px;">' . $total_pages . '</a>';
                    }
                }

                echo '</div>';
            }
            ?>

        <?php
        } else {
            echo '<p>No postbacks received yet.</p>';
        }
        ?>

    </div>
<?php
}

/**
 * Register deactivation hook to clean up plugin transients.
 */
function cf_deactivate()
{
    delete_transient('cf_postback_log');
}
register_deactivation_hook(__FILE__, 'cf_deactivate');
