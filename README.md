# SiteDrop: construction materials store (Bengaluru)

Needs Node.js 22.5 or newer. No npm install needed.

## Run locally
    ADMIN_PASSWORD=pick-a-long-password node server.js
Open http://localhost:3000 (shop) and http://localhost:3000/admin.html (admin).

## Go live (simplest)
1. Put this folder on a host that runs Node 22+ (Render, Railway, Fly.io or a VPS) and attach a persistent disk for the `data/` and `backups/` folders.
2. Set the variables from `.env.example` in the host's settings. ADMIN_PASSWORD is required.
3. Start command: `node --disable-warning=ExperimentalWarning server.js`
4. Point your domain at the host and enable HTTPS, then set SITE_URL to the https address.

## Before you take real orders
- Open /admin.html: set real prices, bulk prices, stock and each product's HSN code (confirm GST rate and HSN with your CA).
- Fill BIZ_* values (legal name, GSTIN, address, phone). They appear on the site, policies and invoices.
- Have the policy pages (/p/terms, /p/privacy, /p/refund, /p/shipping) reviewed by a lawyer.
- Online payments: add Razorpay keys. Without them the site is pay-on-delivery only.
- Order alerts: set NOTIFY_WEBHOOK to a Make/Zapier/WhatsApp-provider webhook URL. New orders are also printed in the server log, and the admin page has one-tap WhatsApp links to customers.
- Daily database backups are kept in `backups/` (last 14). Copy them off the server regularly.

## Customer login, photos and payment webhook
- **Mandatory mobile OTP:** set SMS_PROVIDER=twilio with the TWILIO_* values, or SMS_WEBHOOK to any gateway that accepts a POST of {"phone":"91XXXXXXXXXX","message":"..."}. Indian carriers generally require DLT registration of SMS templates, so an Indian gateway via SMS_WEBHOOK is often preferable. Set a fixed SECRET so verified sessions survive restarts.
- **Photos:** in /admin.html choose an image in a product row, then press Save. Images are stored in `data/uploads/`, so keep that folder on your persistent disk and back it up.
- **Payment webhook:** in the Razorpay dashboard add webhook https://yourdomain.in/api/pay/webhook with events payment.captured and order.paid, and put its secret in RAZORPAY_WEBHOOK_SECRET. If a payment arrives after the order was auto-cancelled, the server re-reserves stock when it can; otherwise the admin page shows "PAID BUT CANCELLED: REFUND NEEDED".


## Upgraded checkout and admin
- Every order requires a mobile number verified by OTP before the order is accepted.
- If Checkout is clicked before verification, the storefront opens OTP verification and returns to checkout after successful verification.
- The storefront remains HTML/CSS/JS, so its visual design can be changed later without changing the order database/API.
- The admin page now has KPIs, live order alerts, browser notifications, order search/filtering, stock warnings, product editing, invoice/WhatsApp actions, and responsive styling.
