# Conversion Forwarder for WordPress

A lightweight WordPress plugin that acts as a server-side event forwarder for conversion tracking.

---

## 📌 What It Does:

It listens for incoming HTTP POST or GET requests (from 3rd party sources like affiliate platforms or tracking systems) and **forwards conversion data** to:

-   ✅ **Facebook Conversions API**
-   ✅ **Google Ads API (Click Conversion Uploads)**

**Key Features:**
- Automatic Google OAuth token refresh
- Comprehensive postback logging with search & filtering
- CSV export for logs and email lists
- Visual analytics with daily charts for **Unique Posts**, **Total Events**, and **Conversions**
- Analytics-first admin UI with native WordPress tabs (**Analytics** and **Settings**)
- Default analytics range set to **current month** (with quick presets)
- Conversion counting via configurable match strings (e.g. `event_name: Purchase`)
- Optional IP-source-based log filtering support (via hooks)
- Configurable storage prefix for multi-instance setups

---

## ✅ Incoming Endpoint:

```
POST/GET https://YOUR_SITE.com/wp-json/convert/v1/forward
```

You can send data via POST or GET. Example tools: Postman, affiliate systems, tracking platforms.

---

## ✅ Supported Input Parameters:

### Click Identifiers (at least one required):
| Parameter   | Type   | Required for | Example                       |
| ----------- | ------ | ------------ | ----------------------------- |
| fbclid      | string | Facebook     | `"fbclid": "FB.12345"`        |
| gclid       | string | Google Ads   | `"gclid": "EAIaIQob"`         |

### Event Data:
| Parameter   | Type   | Required for | Example                       |
| ----------- | ------ | ------------ | ----------------------------- |
| event_name  | string | Facebook     | `"event_name": "Lead"`        |
| value       | number | Both         | `"value": 100`                |
| currency    | string | Both         | `"currency": "USD"`           |

### User Data (Facebook PII - auto-hashed):
| Parameter   | Type   | Example                       |
| ----------- | ------ | ----------------------------- |
| email       | string | `"email": "user@example.com"` |
| phone       | string | `"phone": "+5511912345678"`   |
| first_name  | string | `"first_name": "John"`        |
| last_name   | string | `"last_name": "Doe"`          |
| city        | string | `"city": "Sao Paulo"`         |
| state       | string | `"state": "SP"`               |
| country     | string | `"country": "BR"`             |
| zip         | string | `"zip": "01234-567"`          |
| external_id | string | `"external_id": "user123"`    |

### Custom Data (Facebook):
| Parameter              | Type   | Example                             |
| ---------------------- | ------ | ----------------------------------- |
| predicted_ltv          | number | `"predicted_ltv": 500`              |
| customer_segmentation  | string | `"customer_segmentation": "VIP"`    |
| content_type           | string | `"content_type": "product"`         |
| content_ids            | array  | `"content_ids": ["123", "456"]`     |
| contents               | array  | `"contents": [{"id": "123"}]`       |
| event_id               | string | `"event_id": "unique-event-123"`    |

---

## ✅ Example Payloads:

### Facebook Only (with user data):

```json
{
    "fbclid": "FB.12345",
    "event_name": "Lead",
    "email": "user@example.com",
    "phone": "+5511912345678",
    "first_name": "John",
    "last_name": "Doe",
    "city": "Sao Paulo",
    "state": "SP",
    "country": "BR",
    "zip": "01234-567",
    "external_id": "user123",
    "value": 100
}
```

### Google Ads Only:

```json
{
    "gclid": "EAIaIQob",
    "value": 120
}
```

### Both Together:

```json
{
    "fbclid": "FB.12345",
    "gclid": "EAIaIQob",
    "value": 50,
    "event_name": "Purchase",
    "email": "user@example.com"
}
```

---

## ✅ Admin Settings:

Go to:

```
WordPress Admin → Settings → Conversion Forwarder
```

You’ll see fields to configure:

-   **Facebook API Token**
-   **Facebook Pixel ID**
-   **Google OAuth Client ID / Client Secret / Refresh Token**
-   **Google Ads Developer Token**
-   **Google Ads Customer ID**
-   **Google Ads Conversion Action ID**
-   **Permanent Postbacks Preview Filter** (strings to remove from displayed logs)
-   **Conversion Strings** (one per line or comma-separated) used for conversion counting in analytics

---

## ✅ Analytics View:

The Analytics tab includes:

- Daily chart views with toggle tabs:
    - **Unique Posts** (unique fbclid + gclid per day)
    - **Total Events**
    - **Conversions** (based on configured conversion strings)
- Dynamic chart titles with totals (e.g. `Postbacks by Day (220 Unique fbclid and gclid)`)
- Search and date filters
- Date presets: **Today**, **This week**, **This month**, **All Time**
- Export buttons (Logs and Emails) that respect active filters
- Optional **Filter by IP Sources** button when IP source hooks are provided

---

## ✅ Requirements:

-   For **Facebook**, you need a valid Conversions API Token and Pixel ID.
-   For **Google Ads**, you need:
    -   A Developer Token (from your Google Ads API Console)
    -   Customer ID (your Ads account number)
    -   OAuth Client ID + Client Secret + Refresh Token
    -   Conversion Action ID (configured in your Google Ads account)

---

## ✅ Response Format:

Each API call returns a JSON response:

**Success:**
```json
{
    "status": "completed",
    "message": "Conversion successfully forwarded.",
    "log": {
        "facebook": { ... },
        "google_ads": { ... }
    }
}
```

**Error:**
```json
{
    "status": "error",
    "message": "One or more errors occurred...",
    "errors": {
        "facebook": "Error message",
        "google_ads": "Error message"
    },
    "log": { ... }
}
```

---

## ✅ Developer Hooks:

**Filter IP sources for log filtering:**
```php
// Provide IP source names
add_filter('conversion_forwarder_ips_sources', function($sources) {
    $sources[] = 'My Custom Source';
    return $sources;
});

// Provide IPs to match against logs
add_filter('conversion_forwarder_ips_to_match', function($ips) {
    $ips[] = '192.168.1.100';
    return $ips;
});
```

---

## ✅ Data Handling:

-   **Maximum log entries**: 500,000 (automatically trimmed)
-   **PII hashing**: All Facebook user data is SHA256 hashed before transmission
-   **Storage**: Logs stored in WordPress options table with configurable prefix
-   **CORS**: Endpoint supports cross-origin requests

---

## ✅ Future Improvements:

-   Support for more advertising platforms (TikTok Ads, LinkedIn, etc.)
-   Enhanced event parameter mapping
-   Webhook endpoint configuration
