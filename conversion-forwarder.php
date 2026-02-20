<?php

/**
 * Plugin Name: Conversion Forwarder
 * Description: Forwards incoming conversion postbacks to Facebook Conversions API and Google Ads API.
 * Version: 1.0.4
 * Author: RO
 */

// Exit if accessed directly.
if (!defined('ABSPATH')) {
    exit;
}

// === Constants ===

// Base prefix for all options.
$custom_prefix = get_option('cf_options_prefix', 'cf_');
$custom_prefix = preg_replace('/[^a-zA-Z0-9_]/', '', $custom_prefix);

// Ensure the prefix always starts with "cf_"
if (strpos($custom_prefix, 'cf_') !== 0) {
    $custom_prefix = 'cf_' . ltrim($custom_prefix, '_');
}

// Ensure the prefix always ends with "_"
if (substr($custom_prefix, -1) !== '_') {
    $custom_prefix .= '_';
}

define('CF_OPTIONS_PREFIX', $custom_prefix);

// === Register REST Endpoint ===
add_action('rest_api_init', function () {
    register_rest_route('convert/v1', '/forward', [
        'methods' => ['POST', 'GET', 'OPTIONS'],
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
    $client_id = get_option(CF_OPTIONS_PREFIX . 'google_client_id');
    $client_secret = get_option(CF_OPTIONS_PREFIX . 'google_client_secret');
    $refresh_token = get_option(CF_OPTIONS_PREFIX . 'google_refresh_token');

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
    // === Handle CORS Preflight and Headers ===
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: POST, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");

    // If this is a preflight (OPTIONS) request, return immediately
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        return new WP_REST_Response(null, 200);
    }

    $params = $request->get_params(); // Get all parameters from the incoming request.
    $log = []; // Initialize array to store successful API responses.
    $errors = []; // Initialize array to store any errors encountered.
    $timestamp = time(); // Current Unix timestamp for event timing.
    $current_time = gmdate("Y-m-d\TH:i:s\Z", $timestamp); // Formatted time for Google Ads API.

    // Retrieve Facebook API credentials from WordPress options.
    $fb_token = get_option(CF_OPTIONS_PREFIX . 'fb_token');
    $pixel_id = get_option(CF_OPTIONS_PREFIX . 'fb_pixel_id');

    // Retrieve Google Ads API credentials from WordPress options.
    $google_dev_token = get_option(CF_OPTIONS_PREFIX . 'google_developer_token');
    $google_cust_id = get_option(CF_OPTIONS_PREFIX . 'google_customer_id');
    $google_action_id = get_option(CF_OPTIONS_PREFIX . 'google_conversion_action_id');

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
    $stored_log = get_option(CF_OPTIONS_PREFIX . 'postback_log');

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
    update_option(CF_OPTIONS_PREFIX . 'postback_log', $stored_log);
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
    $log_data = get_option(CF_OPTIONS_PREFIX . 'postback_log');

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
function cf_search_logs($logs, $search_term)
{
    if (!empty($search_term)) {
        $keep = [];
        for ($i = 0; $i < count($logs); $i++) {
            // Create a searchable text representation matching the display format
            $searchable_params = '';
            if (isset($logs[$i]['parameters']) && is_array($logs[$i]['parameters'])) {
                foreach ($logs[$i]['parameters'] as $key => $value) {
                    if (is_bool($value)) {
                        $searchable_params .= $key . ': ' . ($value ? 'true' : 'false') . "\n";
                    } else if (is_array($value) || is_object($value)) {
                        $searchable_params .= $key . ': ' . json_encode($value, JSON_PRETTY_PRINT) . "\n";
                    } else {
                        $searchable_params .= $key . ': ' . $value . "\n";
                    }
                }
            }

            if (
                stripos($logs[$i]['time'], $search_term) !== false || // Match partial date in 'time'
                stripos($logs[$i]['ip'], $search_term) !== false ||
                stripos($logs[$i]['fbclid'], $search_term) !== false ||
                stripos($logs[$i]['gclid'], $search_term) !== false ||
                stripos($searchable_params, $search_term) !== false || // Match in formatted parameters
                stripos(json_encode($logs[$i]['parameters']), $search_term) !== false // Also keep JSON search as fallback
            ) {
                $keep[] = $logs[$i];
            }
        }
        $logs = cf_sort_logs_by_date($keep);
    }

    return $logs;
}

/**
 * Filters log entries based on a date range.
 *
 * @param array $logs The log entries to filter.
 * @param string $start_date The start date (Y-m-d format).
 * @param string $end_date The end date (Y-m-d format).
 * @return array The filtered log entries within the date range.
 */
function cf_filter_logs_by_date($logs, $start_date, $end_date)
{
    if (empty($start_date) && empty($end_date)) {
        return $logs;
    }

    $keep = [];

    foreach ($logs as $entry) {
        // Extract date from entry time (format: Y-m-d)
        $entry_date = substr($entry['time'], 0, 10);

        // Check if entry is within range
        $include = true;

        if (!empty($start_date) && $entry_date < $start_date) {
            $include = false;
        }

        if (!empty($end_date) && $entry_date > $end_date) {
            $include = false;
        }

        if ($include) {
            $keep[] = $entry;
        }
    }

    return $keep;
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
function cf_is_admin_page()
{
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
function cf_get_current_log_page()
{
    $pagination = isset($_GET['pbpage']) ? intval($_GET['pbpage']) : 1; // Get current page number.
    return $pagination;
}

/**
 * Retrieves the current search query from the query parameters.
 *
 * @return string The current search query.
 */
function cf_get_search_query()
{
    $search_query = isset($_GET['search']) ? trim(sanitize_text_field($_GET['search'])) : ''; // Search query.
    $search_query = str_replace(['\"', '\"'], ['"', '"'], $search_query);
    return $search_query;
}

/**
 * Retrieves the date range from the query parameters.
 *
 * @return array An array with 'start' and 'end' date strings (Y-m-d format), or empty strings if not set.
 */
function cf_get_date_range()
{
    $start_date = isset($_GET['start_date']) ? sanitize_text_field($_GET['start_date']) : '';
    $end_date = isset($_GET['end_date']) ? sanitize_text_field($_GET['end_date']) : '';

    // Validate date format (Y-m-d)
    if ($start_date && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $start_date)) {
        $start_date = '';
    }
    if ($end_date && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $end_date)) {
        $end_date = '';
    }

    return [
        'start' => $start_date,
        'end' => $end_date
    ];
}

/**
 * Escape a value for CSV
 */
function cf_csv_escape($value)
{
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
function cf_export_emails()
{
    // Check user permissions
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }

    // Allow filtering the logs by search parameter and date range
    $search_query = cf_get_search_query(); // Get current search query.
    $date_range = cf_get_date_range(); // Get date range.
    $log_data = cf_get_postback_log();
    if (!empty($search_query)) {
        $log_data = cf_search_logs($log_data, $search_query);
    }
    if (!empty($date_range['start']) || !empty($date_range['end'])) {
        $log_data = cf_filter_logs_by_date($log_data, $date_range['start'], $date_range['end']);
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
add_action('admin_init', function () {
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
function cf_export_logs()
{
    // Check user permissions
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }

    // Allow filtering the logs by search parameter and date range
    $search_query = cf_get_search_query(); // Get current search query.
    $date_range = cf_get_date_range(); // Get date range.
    $log_data = cf_get_postback_log();
    if (!empty($search_query)) {
        $log_data = cf_search_logs($log_data, $search_query);
    }
    if (!empty($date_range['start']) || !empty($date_range['end'])) {
        $log_data = cf_filter_logs_by_date($log_data, $date_range['start'], $date_range['end']);
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
add_action('admin_init', function () {
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
    register_setting('cf_settings_group', 'cf_options_prefix');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'fb_token');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'fb_pixel_id');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'google_client_id');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'google_client_secret');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'google_refresh_token');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'google_developer_token');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'google_customer_id');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'google_conversion_action_id');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'postback_filter');
    register_setting('cf_settings_group', CF_OPTIONS_PREFIX . 'conversion_strings');
});

/**
 * Renders the admin settings page for the Conversion Forwarder plugin.
 * This includes input fields for API credentials and a display of recent postbacks.
 */
function cf_settings_page()
{
    $active_tab = (isset($_GET['cf_tab']) && $_GET['cf_tab'] === 'settings') ? 'settings' : 'analytics';
    $analytics_tab_url = admin_url('/options-general.php?page=conversion_forwarder&cf_tab=analytics#recent-postbacks');
    $settings_tab_url = admin_url('/options-general.php?page=conversion_forwarder&cf_tab=settings');
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

        .cf-settings-form .postbox {
            padding: 0 15px;
        }
    </style>
    <div class="wrap">
        <h1>Conversion Forwarder</h1>
        <h2 class="nav-tab-wrapper">
            <a href="<?php echo esc_url($analytics_tab_url); ?>" class="nav-tab <?php echo $active_tab === 'analytics' ? 'nav-tab-active' : ''; ?>">Analytics</a>
            <a href="<?php echo esc_url($settings_tab_url); ?>" class="nav-tab <?php echo $active_tab === 'settings' ? 'nav-tab-active' : ''; ?>">Settings</a>
        </h2>

        <?php if ($active_tab === 'settings') { ?>
        <p>Configure the settings for forwarding conversions to Facebook and Google Ads.</p>
        <form method="post" action="options.php" class="cf-settings-form">
            <?php
            settings_fields('cf_settings_group');
            do_settings_sections('cf_settings_group');
            ?>
            <div class="postbox">
                <h2>Storage</h2>
                <p>All settings are stored in the WordPress options table with a custom prefix.
                    You can change the prefix below if needed. Changing the prefix will make the plugin use a different set of
                    options, effectively resetting your configuration. Note: The prefix will always start with "cf_".</p>
                <p>Current prefix: <strong><?php echo esc_html(CF_OPTIONS_PREFIX); ?></strong></p>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Options Prefix</th>
                        <td><input type="text" name="cf_options_prefix" value="<?php echo esc_attr(get_option('cf_options_prefix', 'cf_')); ?>"
                                size="60" /></td>
                    </tr>
                </table>
            </div>

            <div class="postbox">
                <h2>Facebook API Settings</h2>
                <p>Read the Facebook Conversions API <a
                        href="https://developers.facebook.com/docs/marketing-api/conversions-api/parameters/" target="_blank"
                        rel="noreferrer noopener">documentation</a> for more information on the required parameters.</p>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Facebook Pixel ID</th>
                        <td><input type="text" name="<?php echo CF_OPTIONS_PREFIX ?>fb_pixel_id"
                                value="<?php echo esc_attr(get_option(CF_OPTIONS_PREFIX . 'fb_pixel_id')); ?>" /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Facebook API Token</th>
                        <td><input type="text" name="<?php echo CF_OPTIONS_PREFIX ?>fb_token" value="<?php echo esc_attr(get_option(CF_OPTIONS_PREFIX . 'fb_token')); ?>"
                                size="60" /></td>
                    </tr>
                </table>
            </div>

            <div class="postbox">
                <h2>Google OAuth Settings (for Automatic Token Refresh)</h2>
                <p>These credentials are used to obtain an access token for the Google Ads API. For more information on setting
                    up OAuth, refer to the Google Ads API <a
                        href="https://developers.google.com/google-ads/api/docs/oauth/overview" target="_blank"
                        rel="noreferrer noopener">documentation</a>.</p>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Google OAuth Client ID</th>
                        <td><input type="text" name="<?php echo CF_OPTIONS_PREFIX ?>google_client_id"
                                value="<?php echo esc_attr(get_option(CF_OPTIONS_PREFIX . 'google_client_id')); ?>" size="60" /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Google OAuth Client Secret</th>
                        <td><input type="text" name="<?php echo CF_OPTIONS_PREFIX ?>google_client_secret"
                                value="<?php echo esc_attr(get_option(CF_OPTIONS_PREFIX . 'google_client_secret')); ?>" size="60" /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Google OAuth Refresh Token</th>
                        <td><input type="text" name="<?php echo CF_OPTIONS_PREFIX ?>google_refresh_token"
                                value="<?php echo esc_attr(get_option(CF_OPTIONS_PREFIX . 'google_refresh_token')); ?>" size="60" /></td>
                    </tr>
                </table>

                <h2>Google Ads API Settings</h2>
                <p>These are specific to your Google Ads account. Refer to the Google Ads API <a
                        href="https://developers.google.com/google-ads/api/docs/conversions/overview" target="_blank"
                        rel="noreferrer noopener">documentation</a> for details on conversion actions.</p>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Developer Token</th>
                        <td><input type="text" name="<?php echo CF_OPTIONS_PREFIX ?>google_developer_token"
                                value="<?php echo esc_attr(get_option(CF_OPTIONS_PREFIX . 'google_developer_token')); ?>" /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Customer ID (without hyphens)</th>
                        <td><input type="text" name="<?php echo CF_OPTIONS_PREFIX ?>google_customer_id"
                                value="<?php echo esc_attr(get_option(CF_OPTIONS_PREFIX . 'google_customer_id')); ?>" /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Conversion Action ID</th>
                        <td><input type="text" name="<?php echo CF_OPTIONS_PREFIX ?>google_conversion_action_id"
                                value="<?php echo esc_attr(get_option(CF_OPTIONS_PREFIX . 'google_conversion_action_id')); ?>" /></td>
                    </tr>
                </table>
            </div>

            <div class="postbox">
                <h2>Permanent Postbacks Preview Filter</h2>
                <p>Apply filtering to the displayed postbacks logs.<br><strong>Note:</strong> <em>This does not affect the data sent to the endpoint, only the logs displayed here.</em></p>

                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Strings to Remove (comma-separated)</th>
                        <td><input type="text" name="<?php echo CF_OPTIONS_PREFIX ?>postback_filter"
                                value="<?php echo esc_attr(get_option(CF_OPTIONS_PREFIX . 'postback_filter')); ?>" /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Conversion Strings</th>
                        <td>
                            <textarea name="<?php echo CF_OPTIONS_PREFIX ?>conversion_strings" rows="4" cols="60" placeholder="event_name: Purchase&#10;event_name: Bet"><?php echo esc_textarea(get_option(CF_OPTIONS_PREFIX . 'conversion_strings')); ?></textarea>
                            <p class="description">One per line (or comma-separated). If any string matches a log line, that entry counts as 1 conversion.</p>
                        </td>
                    </tr>
                </table>

                <?php submit_button(); ?>
            </div>

            <div class="postbox">

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
    <?php } ?>

    <?php if ($active_tab === 'analytics') { ?>
    
    <h2 id="recent-postbacks">Recent Postbacks</h2>

    <?php
    // Retrieve the transient log data.
    $log_data = cf_get_postback_log();

    // Get filter parameters
    $search_query = cf_get_search_query();
    $date_range = cf_get_date_range();
    $pagination = cf_get_current_log_page();

    // Default analytics view to current month when no date filter is provided
    if (empty($date_range['start']) && empty($date_range['end'])) {
        $date_range['start'] = date('Y-m-01');
        $date_range['end'] = date('Y-m-d');
    }

    // Store if we have any data at all (before filtering)
    $has_any_data = $log_data && is_array($log_data) && count($log_data) > 0;

    // Apply search and date filters BEFORE building chart
    if (!empty($search_query)) {
        $log_data = cf_search_logs($log_data, $search_query);
    }

    if (!empty($date_range['start']) || !empty($date_range['end'])) {
        $log_data = cf_filter_logs_by_date($log_data, $date_range['start'], $date_range['end']);
    }

    if ($log_data && is_array($log_data) && count($log_data) > 0) {
        $daily_fbclids = [];
        $daily_gclids = [];
        $daily_fb_counts = [];
        $daily_google_counts = [];
        $daily_conversion_counts = [];

        // Sanitize and filter out unwanted strings
        $filter_strings = explode(',', get_option(CF_OPTIONS_PREFIX . 'postback_filter', ''));
        $filter_strings = array_map('trim', $filter_strings);

        // Conversion strings can be one-per-line or comma-separated
        $conversion_strings_raw = get_option(CF_OPTIONS_PREFIX . 'conversion_strings', '');
        $conversion_strings = preg_split('/[\r\n,]+/', (string) $conversion_strings_raw);
        $conversion_strings = array_values(array_filter(array_map(function ($value) {
            return trim(trim($value), ',');
        }, $conversion_strings), function ($value) {
            return $value !== '';
        }));

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
            if (!isset($daily_fb_counts[$day])) {
                $daily_fb_counts[$day] = 0;
            }
            if (!isset($daily_google_counts[$day])) {
                $daily_google_counts[$day] = 0;
            }
            if (!isset($daily_conversion_counts[$day])) {
                $daily_conversion_counts[$day] = 0;
            }

            if (!empty($entry['fbclid'])) {
                $daily_fbclids[$day][$entry['fbclid']] = true;
                $daily_fb_counts[$day]++;
            }
            if (!empty($entry['gclid'])) {
                $daily_gclids[$day][$entry['gclid']] = true;
                $daily_google_counts[$day]++;
            }

            if (!empty($conversion_strings)) {
                $entry_searchable_text = '';
                if (isset($entry['parameters']) && is_array($entry['parameters'])) {
                    foreach ($entry['parameters'] as $key => $value) {
                        if (is_bool($value)) {
                            $entry_searchable_text .= $key . ': ' . ($value ? 'true' : 'false') . "\n";
                        } else if (is_array($value) || is_object($value)) {
                            $entry_searchable_text .= $key . ': ' . json_encode($value, JSON_PRETTY_PRINT) . "\n";
                        } else {
                            $entry_searchable_text .= $key . ': ' . $value . "\n";
                        }
                    }
                }

                $matched_conversion = false;
                foreach ($conversion_strings as $conversion_string) {
                    if (
                        stripos($entry_searchable_text, $conversion_string) !== false ||
                        stripos(json_encode($entry['parameters']), $conversion_string) !== false ||
                        stripos(json_encode($entry), $conversion_string) !== false
                    ) {
                        $matched_conversion = true;
                        break;
                    }
                }

                if ($matched_conversion) {
                    $daily_conversion_counts[$day]++;
                }
            }
        }

        $all_days = array_unique(array_merge(array_keys($daily_fbclids), array_keys($daily_gclids)));
        sort($all_days);

        $labels = $all_days;
        $data_fb_unique = [];
        $data_google_unique = [];
        $data_fb_total = [];
        $data_google_total = [];
        $data_conversions = [];

        foreach ($all_days as $day) {
            $data_fb_unique[] = isset($daily_fbclids[$day]) ? count($daily_fbclids[$day]) : 0;
            $data_google_unique[] = isset($daily_gclids[$day]) ? count($daily_gclids[$day]) : 0;
            $data_fb_total[] = isset($daily_fb_counts[$day]) ? $daily_fb_counts[$day] : 0;
            $data_google_total[] = isset($daily_google_counts[$day]) ? $daily_google_counts[$day] : 0;
            $data_conversions[] = isset($daily_conversion_counts[$day]) ? $daily_conversion_counts[$day] : 0;
        }

        $total_unique_count = array_sum($data_fb_unique) + array_sum($data_google_unique);
        $total_events_count = array_sum($data_fb_total) + array_sum($data_google_total);
        $total_conversions_count = array_sum($data_conversions);
    ?>
        <div style="margin-bottom:10px;text-align:right;margin-top:-40px;">
            <div class="button-group" style="display:inline-flex; border:1px solid #ccc; border-radius:3px; overflow:hidden;">
                <button id="cfViewUnique" class="button cf-view-btn" style="border-radius:0; border:none; background:#0073aa; color:#fff; margin:0;">Unique Postbacks</button>
                <button id="cfViewTotal" class="button cf-view-btn" style="border-radius:0; border:none; margin:0;">Total Events</button>
                <button id="cfViewConversions" class="button cf-view-btn" style="border-radius:0; border:none; margin:0;">Conversions</button>
            </div>
        </div>
        <div style="width:100%; height:300px; margin-bottom:20px;">
            <canvas id="cfPostbackChart"></canvas>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const ctx = document.getElementById('cfPostbackChart');
                if (!ctx) return;

                // Chart data for both views
                const chartData = {
                    labels: <?php echo json_encode($labels); ?>,
                    unique: {
                        fb: <?php echo json_encode($data_fb_unique); ?>,
                        google: <?php echo json_encode($data_google_unique); ?>
                    },
                    total: {
                        fb: <?php echo json_encode($data_fb_total); ?>,
                        google: <?php echo json_encode($data_google_total); ?>
                    },
                    conversions: {
                        values: <?php echo json_encode($data_conversions); ?>
                    },
                    counts: {
                        unique: <?php echo json_encode($total_unique_count); ?>,
                        total: <?php echo json_encode($total_events_count); ?>,
                        conversions: <?php echo json_encode($total_conversions_count); ?>
                    }
                };

                // Initialize chart with unique view
                let currentView = 'unique';

                function buildUniqueDatasets() {
                    return [{
                            label: 'Facebook (fbclid)',
                            data: chartData.unique.fb,
                            backgroundColor: '#3b5998',
                            borderColor: '#3b5998',
                            borderWidth: 1
                        },
                        {
                            label: 'Google (gclid)',
                            data: chartData.unique.google,
                            backgroundColor: '#34a853',
                            borderColor: '#34a853',
                            borderWidth: 1
                        }
                    ];
                }

                function buildTotalDatasets() {
                    return [{
                            label: 'Facebook (fbclid)',
                            data: chartData.total.fb,
                            backgroundColor: '#3b5998',
                            borderColor: '#3b5998',
                            borderWidth: 1
                        },
                        {
                            label: 'Google (gclid)',
                            data: chartData.total.google,
                            backgroundColor: '#34a853',
                            borderColor: '#34a853',
                            borderWidth: 1
                        }
                    ];
                }

                function buildConversionsDataset() {
                    return [{
                        label: 'Conversions',
                        data: chartData.conversions.values,
                        backgroundColor: '#0073aa',
                        borderColor: '#0073aa',
                        borderWidth: 1
                    }];
                }

                const chart = new Chart(ctx.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: chartData.labels,
                        datasets: buildUniqueDatasets()
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
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
                                    text: 'Count'
                                },
                                ticks: {
                                    precision: 0
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                position: 'top',
                            },
                            title: {
                                display: true,
                                text: 'Postbacks by Day (' + chartData.counts.unique + ' Unique fbclid and gclid)'
                            }
                        }
                    }
                });

                // Toggle button styling
                function updateButtonStyles(activeBtn) {
                    document.querySelectorAll('.cf-view-btn').forEach(btn => {
                        btn.style.background = '#f0f0f1';
                        btn.style.color = '#2c3338';
                    });
                    activeBtn.style.background = '#0073aa';
                    activeBtn.style.color = '#fff';
                }

                // Switch to unique view
                document.getElementById('cfViewUnique').addEventListener('click', function() {
                    if (currentView === 'unique') return;
                    currentView = 'unique';

                    chart.data.datasets = buildUniqueDatasets();
                    chart.options.plugins.title.text = 'Postbacks by Day (' + chartData.counts.unique + ' Unique fbclid and gclid)';
                    chart.update();

                    updateButtonStyles(this);
                });

                // Switch to total view
                document.getElementById('cfViewTotal').addEventListener('click', function() {
                    if (currentView === 'total') return;
                    currentView = 'total';

                    chart.data.datasets = buildTotalDatasets();
                    chart.options.plugins.title.text = 'Postbacks by Day (' + chartData.counts.total + ' Total Events)';
                    chart.update();

                    updateButtonStyles(this);
                });

                // Switch to conversions view
                document.getElementById('cfViewConversions').addEventListener('click', function() {
                    if (currentView === 'conversions') return;
                    currentView = 'conversions';

                    chart.data.datasets = buildConversionsDataset();
                    chart.options.plugins.title.text = 'Postbacks by Day (' + chartData.counts.conversions + ' Conversions)';
                    chart.update();

                    updateButtonStyles(this);
                });
            });
        </script>

    <?php
    } // End chart if block
    ?>

    <div class="cf-row" style="display: flex;grid-template-columns: 1fr 1fr;justify-content: space-between;">
        <div class="row">
            <form method="GET" action="<?php echo admin_url('/options-general.php#conversion-log') ?>">
                <input type="hidden" name="page" value="conversion_forwarder" />
                <input type="hidden" name="cf_tab" value="analytics" />
                <input type="text" name="search" value="<?php echo esc_attr($search_query); ?>"
                    placeholder="Search..." />
                <input type="submit" value="Search" class="button" />
            </form>
            <p style="margin-top: 3px; font-size: 10px;">
                <a href="<?php echo admin_url('/options-general.php?page=conversion_forwarder&cf_tab=analytics#recent-postbacks'); ?>">Clear all filters</a>
            </p>
        </div>

        <div class="row">
            <form method="GET" action="<?php echo admin_url('/options-general.php#conversion-log') ?>" style="display: flex; gap: 5px; align-items: center;">
                <input type="hidden" name="page" value="conversion_forwarder" />
                <input type="hidden" name="cf_tab" value="analytics" />
                <?php if (!empty($search_query)) { ?>
                    <input type="hidden" name="search" value="<?php echo esc_attr($search_query); ?>" />
                <?php } ?>
                <label for="start_date" style="margin: 0;">From:</label>
                <input type="date" id="start_date" name="start_date" value="<?php echo esc_attr($date_range['start']); ?>" />
                <label for="end_date" style="margin: 0;">To:</label>
                <input type="date" id="end_date" name="end_date" value="<?php echo esc_attr($date_range['end']); ?>" />
                <input type="submit" value="Filter" class="button" />
                <?php if (!empty($date_range['start']) || !empty($date_range['end'])) { ?>
                    <a href="<?php echo admin_url('/options-general.php?page=conversion_forwarder&cf_tab=analytics' . (!empty($search_query) ? '&search=' . urlencode($search_query) : '') . '#recent-postbacks'); ?>" class="button">Clear</a>
                <?php } ?>
            </form>
            <?php
            // Calculate date ranges for quick filters
            $today = date('Y-m-d');
            $week_start = date('Y-m-d', strtotime('monday this week'));
            $week_end = $today;
            $month_start = date('Y-m-01');
            $month_end = $today;

            $search_param = !empty($search_query) ? '&search=' . urlencode($search_query) : '';
            ?>
            <p style="margin-top: 3px; font-size: 10px;">
                Presets:
                <a href="<?php echo admin_url('/options-general.php?page=conversion_forwarder&cf_tab=analytics&start_date=' . $today . '&end_date=' . $today . $search_param . '#recent-postbacks'); ?>">Today</a> |
                <a href="<?php echo admin_url('/options-general.php?page=conversion_forwarder&cf_tab=analytics&start_date=' . $week_start . '&end_date=' . $week_end . $search_param . '#recent-postbacks'); ?>">This week</a> |
                <a href="<?php echo admin_url('/options-general.php?page=conversion_forwarder&cf_tab=analytics&start_date=' . $month_start . '&end_date=' . $month_end . $search_param . '#recent-postbacks'); ?>">This month</a> |
                <a href="<?php echo admin_url('/options-general.php?page=conversion_forwarder&cf_tab=analytics' . $search_param . '#recent-postbacks'); ?>">All Time</a>
            </p>
        </div>

        <div class="row">
            <?php
            $export_params = 'search=' . urlencode($search_query);
            if (!empty($date_range['start'])) {
                $export_params .= '&start_date=' . urlencode($date_range['start']);
            }
            if (!empty($date_range['end'])) {
                $export_params .= '&end_date=' . urlencode($date_range['end']);
            }
            ?>
            <a href="<?php echo esc_url_raw(admin_url('/options-general.php?page=conversion_forwarder&cf_tab=analytics&action=export_logs&' . $export_params)) ?>" class="button"><?php echo __('Export Logs') ?></a>
            <p style="margin-top: 3px; font-size: 10px;">Search and date filters will be applied.</p>
        </div>

        <div class="row">
            <a href="<?php echo esc_url_raw(admin_url('/options-general.php?page=conversion_forwarder&cf_tab=analytics&action=export_emails&' . $export_params)) ?>" class="button"><?php echo __('Export Emails') ?></a>
            <p style="margin-top: 3px; font-size: 10px;">Search and date filters will be applied.</p>
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
            $filter_by_ip_url = add_query_arg('cf_tab', 'analytics', $filter_by_ip_url);
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
    // Check if we have filtered data to display
    if ($log_data && is_array($log_data) && count($log_data) > 0) {
        $items_per_page = 100;

        // Paginate the log data.
        $total_items = count($log_data);
        $total_pages = ceil($total_items / $items_per_page);
        $offset = ($pagination - 1) * $items_per_page;

        $log_data = array_slice($log_data, $offset, $items_per_page);
    ?>

        <p>Displaying page <?php echo $pagination; ?> of <?php echo $total_pages; ?>. Total postbacks:
            <?php echo $total_items; ?>.
        </p>

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

            // Build query params for pagination links
            $query_params = [];
            if (!empty($search_query)) {
                $query_params[] = 'search=' . urlencode($search_query);
            }
            if (!empty($date_range['start'])) {
                $query_params[] = 'start_date=' . urlencode($date_range['start']);
            }
            if (!empty($date_range['end'])) {
                $query_params[] = 'end_date=' . urlencode($date_range['end']);
            }
            $query_string = !empty($query_params) ? '&' . implode('&', $query_params) : '';

            // Show all pages if within max_visible limit
            if ($total_pages <= $max_visible) {
                for ($i = 1; $i <= $total_pages; $i++) {
                    if ($i === $pagination) {
                        echo '<span class="tablenav-page tablenav-page-current" style="margin-left: 5px;">' . $i . '</span>';
                    } else {
                        echo '<a class="tablenav-page" href="?page=conversion_forwarder&cf_tab=analytics&pbpage=' . $i . $query_string . '#recent-postbacks" style="margin-left: 5px;">' . $i . '</a>';
                    }
                }
            }
            // Show a moving window of pages
            else {
                // Always show first page
                if ($pagination == 1) {
                    echo '<span class="tablenav-page tablenav-page-current" style="margin-left: 5px;">1</span>';
                } else {
                    echo '<a class="tablenav-page" href="?page=conversion_forwarder&cf_tab=analytics&pbpage=1' . $query_string . '#recent-postbacks" style="margin-left: 5px;">1</a>';
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
                        echo '<a class="tablenav-page" href="?page=conversion_forwarder&cf_tab=analytics&pbpage=' . $i . $query_string . '#recent-postbacks" style="margin-left: 5px;">' . $i . '</a>';
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
                    echo '<a class="tablenav-page" href="?page=conversion_forwarder&cf_tab=analytics&pbpage=' . $total_pages . $query_string . '#recent-postbacks" style="margin-left: 5px;">' . $total_pages . '</a>';
                }
            }

            echo '</div>';
        }
        ?>

    <?php
    } else {
        // Show appropriate message based on whether we have any data at all
        if ($has_any_data) {
            echo '<p>No postbacks found matching your filters.</p>';
        } else {
            echo '<p>No postbacks received yet.</p>';
        }
    }
    ?>

        <?php } ?>

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
