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

| Parameter   | Type   | Required for | Example                       |
| ----------- | ------ | ------------ | ----------------------------- |
| fbclid      | string | Facebook     | `"fbclid": "FB.12345"`        |
| gclid       | string | Google Ads   | `"gclid": "EAIaIQob"`         |
| gbraid      | string | Google Ads   | `"gbraid": "some_id"`         |
| event_name  | string | Facebook     | `"event_name": "Lead"`        |
| value       | number | Both         | `"value": 100`                |
| email       | string | Facebook     | `"email": "user@example.com"` |
| phone       | string | Facebook     | `"phone": "+5511912345678"`   |
| first_name  | string | Facebook     | `"first_name": "John"`        |
| last_name   | string | Facebook     | `"last_name": "Doe"`          |
| city        | string | Facebook     | `"city": "Sao Paulo"`         |
| state       | string | Facebook     | `"state": "SP"`               |
| country     | string | Facebook     | `"country": "BR"`             |
| zip         | string | Facebook     | `"zip": "01234-567"`          |
| external_id | string | Facebook     | `"external_id": "user123"`    |

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

Additionally, a log of recent postbacks is stored and available in your WordPress backend (under the plugin settings area).

---

## ✅ Disclaimer:

This plugin does **not handle OAuth token generation for Google Ads**.  
You must generate the OAuth access token separately and paste it in the settings page.

---

## ✅ Future Improvements:

-   Support for more advertising platforms (TikTok Ads, LinkedIn, etc.)
-   Built-in OAuth flow for Google Ads (coming soon)
-   More flexible event parameter mapping
