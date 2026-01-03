# Skillstarter (one-site MVP)

This is a single website that includes:
- Accounts (client / creator / parent / admin)
- Listings directory
- Requests → orders
- Parent consent (required before payment)
- Order chat (basic safety filter)
- Delivery + completion + reviews
- Reporting + admin report dashboard
- Stripe Checkout payments (platform fee added to total)

## Run locally
1) Install deps
```bash
npm install
```

2) Init database
```bash
npm run db:init
```

3) Copy env
```bash
cp .env.example .env
# edit .env (SESSION_SECRET, STRIPE_SECRET_KEY, SITE_URL)
```

4) Start
```bash
npm run dev
```

Open http://localhost:3000

Default local admin:
- admin@skillstarter.local
- Admin123!

## Notes (important)
- For production: change/remove the default admin and use a strong password.
- This MVP marks orders as paid after checkout session creation (simple). For a real launch, add Stripe webhooks to verify payment properly.
- Payouts to parents are manual in this MVP (to keep everything in one site and simple). If you want auto payouts, we can upgrade to Stripe Connect.
