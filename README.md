# Conversion Forwarder for WordPress

A lightweight WordPress plugin that acts as a server-side event forwarder for conversion tracking.

---

## 📌 What It Does:

It listens for incoming HTTP POST or GET requests (from 3rd party sources like affiliate platforms or tracking systems) and **forwards conversion data** to:

-   ✅ **Facebook Conversions API**
-   ✅ **Google Ads API (Click Conversion Uploads)**

---

## ✅ Incoming Endpoint:

```
POST https://YOUR_SITE.com/wp-json/convert/v1/forward
```

You can send data via POST or GET. Example tools: Postman, affiliate systems, tracking platforms.

---

## ✅ Supported Input Parameters:

| Parameter  | Type   | Required for     | Example                |
| ---------- | ------ | ---------------- | ---------------------- |
| fbclid     | string | Facebook         | `"fbclid": "FB.12345"` |
| gclid      | string | Google Ads       | `"gclid": "EAIaIQob"`  |
| gbraid     | string | Google Ads       | `"gbraid": "some_id"`  |
| event_name | string | Facebook         | `"event_name": "Lead"` |
| value      | number | Google Ads       | `"value": 100`         |
| ...        | ...    | Extend as needed |                        |

---

## ✅ Example Payloads:

### Facebook Only:

```json
{
    "fbclid": "FB.12345",
    "event_name": "Lead"
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
    "event_name": "Purchase"
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
-   **Google Ads OAuth Token**
-   **Google Ads Developer Token**
-   **Google Ads Customer ID**
-   **Google Ads Conversion Action ID**

---

## ✅ Requirements:

-   For **Facebook**, you need a valid Conversions API Token and Pixel ID.
-   For **Google Ads**, you need:
    -   A Developer Token (from your Google Ads API Console)
    -   Customer ID (your Ads account number)
    -   OAuth Access Token (you’ll need to generate this from Google OAuth flow)
    -   Conversion Action ID (configured in your Google Ads account)

---

## ✅ Logging:

For each call, the plugin will return a JSON showing the forwarding status and any API responses.

---

## ✅ Disclaimer:

This plugin does **not handle OAuth token generation for Google Ads**.  
You must generate the OAuth access token separately and paste it in the settings page.
